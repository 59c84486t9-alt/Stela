//! Physical AP lifetime and processor-local native resources. Startup ACKs
//! prove entry/ownership only; the runtime publication protocol separately
//! requires an actual recovered native loan before any CPU settlement.
use super::{bootstrap, firmware, resources, topology};
use crate::{
    apic::{self, Apic},
    engine::{host, interrupts},
    handoff::Handoff,
    layout,
    tables::PAGE,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    arch::asm,
    cell::UnsafeCell,
    sync::atomic::{AtomicU8, Ordering},
};

mod mailbox;

const STARTING: u8 = 0;
const READY: u8 = 1;
const REFUSED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupFailure {
    Resources,
    Bootstrap(&'static str),
    EarlyException {
        slot: usize,
        cause: bootstrap::EarlyFault,
    },
    Delivery(apic::StartupError),
    FirmwareTopology(topology::Refusal),
    FirmwareInit {
        processor_number: u32,
        apic_id: u64,
        cause: apic::StartupError,
    },
    Timeout {
        slot: usize,
    },
    Refused {
        slot: usize,
        reason: &'static str,
    },
}

/// This object and its descriptors remain pinned for the whole boot, even
/// after a startup timeout or a parked worker: NMI/MCE can still enter them.
struct Argument {
    processor: topology::Processor,
    source: topology::Snapshot,
    effective_pat: u64,
    stack_bottom: u64,
    stack_top: u64,
    config: UnsafeCell<Option<host::Config>>,
    tables: UnsafeCell<Option<&'static mut interrupts::Tables>>,
    observed: UnsafeCell<Option<topology::Snapshot>>,
    descriptors: UnsafeCell<Option<interrupts::Observation>>,
    doorbells: UnsafeCell<Option<&'static core::sync::atomic::AtomicU64>>,
    refusal: UnsafeCell<Option<&'static str>>,
    status: AtomicU8,
    mailbox: mailbox::Mailbox,
}

// SAFETY: the BSP initializes immutable identity/source fields before SIPI.
// Only the assigned physical AP takes config/tables and writes observed, once;
// a Release status publication precedes every BSP observation. No Cpu, Host,
// guest bytes or runtime native loan are made Send/Sync by this startup record.
unsafe impl Sync for Argument {}

pub(crate) struct Processor {
    slot: usize,
    argument: &'static Argument,
}

impl Processor {
    pub(crate) fn slot(&self) -> usize {
        self.slot
    }
    pub(crate) fn apic_id(&self) -> u64 {
        self.argument.processor.apic_id
    }

    /// This is startup evidence, never runtime quiescence authority.
    pub(crate) fn observation(&self) -> &topology::Snapshot {
        assert_eq!(self.argument.status.load(Ordering::Acquire), READY);
        // SAFETY: the owning AP wrote this once before Release READY and never
        // changes it; the record stays pinned for the complete executor life.
        unsafe {
            (&*self.argument.observed.get())
                .as_ref()
                .expect("ready AP observation")
        }
    }

    pub(crate) fn descriptors(&self) -> interrupts::Observation {
        assert_eq!(self.argument.status.load(Ordering::Acquire), READY);
        // SAFETY: one immutable publication before READY, retained for boot.
        unsafe { (&*self.argument.descriptors.get()).expect("ready AP descriptors") }
    }

    /// Directed interrupt completion evidence only; this never grants a
    /// stopped generation or returned native frame to the runtime.
    pub(crate) unsafe fn check_doorbell(
        &self,
        sender: &Apic,
        tsc_hz: u64,
    ) -> Result<u64, StartupFailure> {
        if self.argument.status.load(Ordering::Acquire) != READY {
            return Err(StartupFailure::Refused {
                slot: self.slot,
                reason: "executor is not ready",
            });
        }
        // SAFETY: the AP published this pinned read-only atomic reference before
        // READY. No Cpu, native frame, Host or recovery state is read here.
        let counter = unsafe { (&*self.argument.doorbells.get()).as_ref().copied() }
            .ok_or(StartupFailure::Resources)?;
        let before = counter.load(Ordering::Acquire);
        // SAFETY: caller owns the BSP ICR and this AP's private IDT is ready.
        unsafe {
            sender.notify(
                u32::try_from(self.apic_id()).map_err(|_| StartupFailure::Resources)?,
                interrupts::NATIVE_WAKE_VECTOR,
                tsc_hz,
            )
        }
        .map_err(StartupFailure::Delivery)?;
        let started = apic::rdtsc();
        while counter.load(Ordering::Acquire) == before {
            if apic::rdtsc().wrapping_sub(started) >= tsc_hz {
                return Err(StartupFailure::Timeout { slot: self.slot });
            }
            core::hint::spin_loop();
        }
        Ok(counter.load(Ordering::Acquire))
    }
}

pub(crate) struct Executors {
    /// BSP is deliberately absent: it already owns its local HostOwner.
    processors: Vec<Processor>,
}

impl Executors {
    pub(crate) fn processors(&self) -> &[Processor] {
        &self.processors
    }
}

unsafe extern "sysv64" fn enter(argument: u64) -> ! {
    // SAFETY: BSP supplied one pinned Argument to exactly this physical AP.
    let argument = unsafe { &*(argument as *const Argument) };
    // SAFETY: this AP alone consumes its descriptor owner, once, before any
    // interrupts/native calls can use this CPU's GS/IST/private handler.
    let tables = unsafe {
        (&mut *argument.tables.get())
            .take()
            .expect("AP descriptors")
    };
    let tables_pointer = tables as *const interrupts::Tables;
    unsafe {
        interrupts::install_on(tables, interrupts::interrupt);
    }
    let initialized = (|| {
        // SAFETY: CPL0 on the actual selected AP, with private descriptors.
        let observed =
            unsafe { firmware::observe() }.map_err(|_| "AP source-control capture refused")?;
        if !observed.matches(argument.processor) {
            return Err("AP physical identity changed");
        }
        // SAFETY: this AP alone consumes its private disjoint host resources.
        let mut config = unsafe {
            (&mut *argument.config.get())
                .take()
                .ok_or("AP resources absent")?
        };
        observed
            .qualify_native(matches!(
                config.placement,
                stela_runtime::machine::mmu::placement::Placement::FiveLevel
            ))
            .map_err(|_| "AP native controls refused")?;
        // The trampoline installs the BSP's already-qualified effective PAT;
        // The offline trampoline installed the complete validated BSP image.
        let source = topology::Snapshot {
            pat: argument.effective_pat,
            ..argument.source
        };
        observed
            .same_memory_types(&source)
            .map_err(|_| "AP memory types differ")?;
        config.apic_base = observed.apic_base;
        let loader_root = config.window_root;
        // SAFETY: configured pool/arena/bounce entries belong only to this AP;
        // tables/local record remain pinned through every native call and park.
        let mut owner =
            unsafe { host::install(config) }.map_err(|_| "AP private host installation failed")?;
        super::context_check::check(&mut owner.host())?;
        // Retain the actual installed private root/control state, not the
        // earlier loader root observed before Host initialization.
        let installed =
            unsafe { firmware::observe() }.map_err(|_| "AP installed-control capture refused")?;
        if installed.cr3 == loader_root || !installed.matches(argument.processor) {
            return Err("AP private root or physical identity differs");
        }
        let descriptors = unsafe { interrupts::observe() };
        if !(argument.stack_bottom..argument.stack_top).contains(&descriptors.rsp)
            || !unsafe { &*tables_pointer }.matches(descriptors)
        {
            return Err("AP private descriptor or stack differs");
        }
        // SAFETY: only this AP publishes these immutable observations, before
        // Release READY. The counter lives in its permanently pinned GS record.
        unsafe {
            *argument.observed.get() = Some(installed);
            *argument.descriptors.get() = Some(descriptors);
            *argument.doorbells.get() = Some(host::doorbell_counter());
        }
        Ok(owner)
    })();
    match initialized {
        Ok(mut owner) => {
            argument.status.store(READY, Ordering::Release);
            let mut worker = None;
            loop {
                if argument.mailbox.poll(&mut owner, &mut worker) {
                    continue;
                }
                // STI's interrupt shadow includes HLT: a pending 0x60 wakes
                // this AP without a poll-to-sleep lost-notification window.
                unsafe {
                    asm!("sti", "hlt", "cli", options(nomem, nostack));
                }
            }
        }
        Err(reason) => {
            // SAFETY: only this AP writes the immutable reason before Release
            // REFUSED. The BSP reads it only after the matching Acquire.
            unsafe { *argument.refusal.get() = Some(reason) };
            argument.status.store(REFUSED, Ordering::Release);
            // Host state may not exist after refusal, so keep maskable IRQs
            // disabled rather than route a doorbell into an uninstalled Host.
            loop {
                unsafe {
                    asm!("cli", "hlt", options(nomem, nostack));
                }
            }
        }
    }
}

/// Remove every enabled firmware AP from its idle code before reclaiming boot
/// services RAM, including APs that will later receive owned startup/SIPI.
/// No AP stack, callback, heap allocation or execution acknowledgement is used.
/// Intel SDM3A, "Local APIC State After an INIT Reset (Wait-for-SIPI State)";
/// UEFI PI MP Services' firmware idle state is not a Stela-owned executor.
///
/// # Safety
/// Run immediately after EBS and before reusing any firmware boot-services RAM,
/// on the captured BSP with IF clear and exclusive access to its local ICR.
/// `capture` is the immutable loader-owned copy, validated before EBS. `sender`
/// addresses the live local APIC (identity UC mapping or x2APIC), and `tsc_hz`
/// is the calibrated source clock. No firmware call may follow. Keep all AP
/// resources retained on delivery failure; no uncertain AP is admitted here.
pub(crate) unsafe fn quiesce_firmware_aps(
    capture: &firmware::Capture,
    sender: &Apic,
    tsc_hz: u64,
) -> Result<usize, StartupFailure> {
    let source = capture
        .processors
        .get(..capture.processor_count as usize)
        .ok_or(StartupFailure::Resources)?;
    let selected = capture
        .selected
        .get(..capture.core_count as usize)
        .filter(|selected| !selected.is_empty())
        .ok_or(StartupFailure::Resources)?;
    // Validate the entire captured assignment before exposing any target. Only
    // the BSP is excluded from INIT at this boundary; selected APs still use
    // firmware idle code until their later owned INIT/SIPI sequence.
    let _validated =
        topology::enabled_unselected(source, selected).map_err(StartupFailure::FirmwareTopology)?;
    let targets = topology::enabled_unselected(source, &selected[..1])
        .map_err(StartupFailure::FirmwareTopology)?;
    if source[selected[0] as usize].apic_id != u64::from(sender.id()) {
        return Err(StartupFailure::Bootstrap(
            "firmware BSP differs from the live local APIC",
        ));
    }
    if tsc_hz == 0 {
        return Err(StartupFailure::Delivery(
            apic::StartupError::ClockUnavailable,
        ));
    }
    // Validate every destination before sending the first INIT: a wide xAPIC
    // target, duplicate source identity or malformed assignment fails closed.
    let destination = |index: usize| -> Result<u32, StartupFailure> {
        let processor = source[index];
        let failure = |cause| StartupFailure::FirmwareInit {
            processor_number: processor.processor_number,
            apic_id: processor.apic_id,
            cause,
        };
        let id = u32::try_from(processor.apic_id)
            .map_err(|_| failure(apic::StartupError::DestinationTooWide))?;
        sender.validate_init(id, tsc_hz).map_err(failure)?;
        Ok(id)
    };
    for index in targets.clone() {
        destination(index)?;
    }
    let mut delivered = 0;
    for index in targets {
        let processor = source[index];
        let id = destination(index)?;
        // SAFETY: source identity, actual BSP exclusion, full destination set
        // and source clock were checked before any effect. No SIPI is sent.
        unsafe { sender.init_only(id, tsc_hz) }.map_err(|cause| StartupFailure::FirmwareInit {
            processor_number: processor.processor_number,
            apic_id: processor.apic_id,
            cause,
        })?;
        delivered += 1;
        crate::output::arguments(format_args!(
            "NATIVE FIRMWARE INIT delivered apic={id:#x} firmware_cpu={} destination_ack=unobserved\n",
            processor.processor_number,
        ));
    }
    Ok(delivered)
}

/// Start the selected physical APs using Stela-owned resources after EBS.
///
/// # Safety
/// Runs only on the validated BSP with interrupts disabled and its local Host
/// installed. The immutable loader capture and every reserved stack/root/code/
/// pool/bounce/physmap mapping stay pinned through this boot. RAM ranges remain
/// owned and immutable as metadata. The caller already called native_smp::validate.
/// The post-EBS loader already called quiesce_firmware_aps before reclaiming
/// firmware boot-services RAM; INIT delivery is not an AP READY observation.
/// No native guest execution is admitted merely by returning this startup set.
pub(crate) unsafe fn start(
    handoff: &'static Handoff,
    capture: &'static firmware::Capture,
    ram: &[host::RamRange],
    tsc_base: u64,
) -> Result<Executors, StartupFailure> {
    let cores = handoff.native_resources.cores as usize;
    if cores == 0 || cores > capture.core_count as usize || handoff.tsc_hz == 0 {
        return Err(StartupFailure::Resources);
    }
    let sender = Apic::new(
        handoff.apic_base,
        layout::physical(handoff.apic_base & apic::BASE_ADDRESS),
    );
    let mut processors = Vec::with_capacity(cores - 1);
    // SAFETY: CPL0, actual BSP; PAT exists under the validated native floor.
    let memory_source = unsafe { firmware::observe() }.map_err(|_| StartupFailure::Resources)?;
    let source_expected = topology::Snapshot {
        pat: memory_source.pat,
        ..capture.snapshots[0]
    };
    memory_source
        .same_memory_types(&source_expected)
        .map_err(|_| StartupFailure::Resources)?;
    let memory_types = super::memory_types::Image::from_snapshot(&memory_source)
        .map_err(StartupFailure::Bootstrap)?;
    if memory_types.amd.is_some() {
        for range in ram {
            memory_types
                .writeback_ram(range.host, range.bytes)
                .map_err(StartupFailure::Bootstrap)?;
        }
        for region in [
            handoff.heap,
            handoff.code,
            handoff.pool,
            handoff.native_resources.stacks,
        ] {
            memory_types
                .writeback_ram(region.physical, region.bytes)
                .map_err(StartupFailure::Bootstrap)?;
        }
        if cores > 1 {
            memory_types
                .writeback_ram(handoff.native_resources.sipi, PAGE)
                .map_err(StartupFailure::Bootstrap)?;
        }
    }
    let effective_pat = memory_source.pat;
    for slot in 1..cores {
        let part = resources::partition(cores, slot, handoff.code.bytes, handoff.pool.bytes)
            .map_err(|_| StartupFailure::Resources)?;
        let processor = capture.processors[capture.selected[slot] as usize];
        let destination =
            u32::try_from(processor.apic_id).map_err(|_| StartupFailure::Resources)?;
        let config = host::Config {
            ram: ram.to_vec(),
            pool_physical: handoff.pool.physical + part.pool_offset,
            pool_bytes: part.pool_bytes,
            window_root: handoff.root,
            code_virtual: layout::code() + part.code_offset,
            code_physical: handoff.code.physical + part.code_offset,
            code_bytes: part.code_bytes,
            tsc_base,
            tsc_hz: handoff.tsc_hz,
            apic_base: capture.snapshots[slot].apic_base,
            placement: handoff.placement,
            bounce: Some((
                layout::bounce() + slot as u64 * 2 * PAGE,
                handoff.native_resources.bounce[slot],
            )),
        };
        let argument: &'static Argument = Box::leak(Box::new(Argument {
            processor,
            source: memory_source,
            effective_pat,
            stack_bottom: layout::stack() + slot as u64 * resources::STACK_STRIDE + PAGE,
            stack_top: layout::stack()
                + slot as u64 * resources::STACK_STRIDE
                + PAGE
                + resources::STACK_BYTES,
            config: UnsafeCell::new(Some(config)),
            tables: UnsafeCell::new(Some(Box::leak(Box::new(interrupts::Tables::new())))),
            observed: UnsafeCell::new(None),
            descriptors: UnsafeCell::new(None),
            doorbells: UnsafeCell::new(None),
            refusal: UnsafeCell::new(None),
            status: AtomicU8::new(STARTING),
            mailbox: mailbox::Mailbox::new(),
        }));
        let physical = handoff.native_resources.sipi;
        crate::output::arguments(format_args!(
            "NATIVE ATTEMPT slot={slot} apic={:#x} firmware_cpu={} package={} core={} thread={} sipi={physical:#x} stack={:#x}..{:#x}\n",
            processor.apic_id,
            processor.processor_number,
            processor.location.package,
            processor.location.core,
            processor.thread,
            argument.stack_bottom,
            argument.stack_top,
        ));
        // SAFETY: this one owned low page has no previous reader: the preceding
        // AP acknowledged high-window entry after its last low-page fetch.
        let vector = unsafe {
            bootstrap::prepare(
                layout::physical(physical) as *mut u8,
                physical,
                bootstrap::Entry {
                    processor_signature: capture.snapshots[slot]
                        .get(1, 0)
                        .ok_or(StartupFailure::Resources)?
                        .eax,
                    root: handoff.root,
                    five_level: matches!(
                        handoff.placement,
                        stela_runtime::machine::mmu::placement::Placement::FiveLevel
                    ),
                    pat: effective_pat,
                    memory_types: &memory_types,
                    stack_top: layout::stack()
                        + slot as u64 * resources::STACK_STRIDE
                        + PAGE
                        + resources::STACK_BYTES,
                    argument: argument as *const Argument as u64,
                    entry: enter,
                },
            )
        }
        .map_err(StartupFailure::Bootstrap)?;
        // Only the BSP writes the shared boot log. Persist the last completed
        // preparation before any real INIT/SIPI can fault or reset the machine;
        // a buffered ATTEMPT alone does not localize an early hardware stop.
        crate::output::arguments(format_args!(
            "NATIVE PREPARED slot={slot} apic={destination:#x} vector={vector:#x} root={:#x}\n",
            handoff.root,
        ));
        crate::output::flush_log();
        // SAFETY: validated physical AP and pinned complete startup resources.
        unsafe { sender.startup(destination, vector, handoff.tsc_hz) }
            .map_err(StartupFailure::Delivery)?;
        crate::output::arguments(format_args!(
            "NATIVE SIPI delivered slot={slot} vector={vector:#x}\n"
        ));
        let before = apic::rdtsc();
        loop {
            // A sealed hardware exception is an actual failed startup, not a
            // timeout or a synthetic READY. Return without reusing any owned
            // AP/low-page resource whose execution remains uncertain.
            if let Some(cause) =
                unsafe { bootstrap::failure(layout::physical(physical) as *const u8) }
                    .map_err(StartupFailure::Bootstrap)?
            {
                return Err(StartupFailure::EarlyException { slot, cause });
            }
            match argument.status.load(Ordering::Acquire) {
                READY => break,
                REFUSED => {
                    // SAFETY: the owner published this immutable reason before
                    // the Acquire REFUSED observation; storage remains pinned.
                    let reason =
                        unsafe { *argument.refusal.get() }.expect("refused AP publishes a reason");
                    return Err(StartupFailure::Refused { slot, reason });
                }
                _ if apic::rdtsc().wrapping_sub(before) >= handoff.tsc_hz => {
                    return Err(StartupFailure::Timeout { slot });
                }
                _ => core::hint::spin_loop(),
            }
        }
        let processor = Processor { slot, argument };
        let installed = processor.observation();
        let descriptors = processor.descriptors();
        // This is the actual Acquire READY publication after high entry,
        // private Host/context qualification and retained observations. Flush
        // before the next slot can reuse the low page; no new success flag or
        // runtime stopped-worker authority is inferred from the log record.
        crate::output::arguments(format_args!(
            "NATIVE READY slot={slot} apic={destination:#x} cr3={:#x} cr0={:#x} cr4={:#x} efer={:#x} pat={:#x} rsp={:#x} gdt={:#x} idt={:#x} gs={:#x}\n",
            installed.cr3,
            installed.cr0,
            installed.cr4,
            installed.efer,
            installed.pat,
            descriptors.rsp,
            descriptors.gdt,
            descriptors.idt,
            descriptors.gs,
        ));
        crate::output::flush_log();
        processors.push(processor);
    }
    Ok(Executors { processors })
}
