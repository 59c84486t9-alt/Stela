//! Page-table/UC/IOAPIC source composition. This bounded diagnostic
//! publishes no Linux driver and checks no physical hardware profile.
use super::*;
use crate::{
    engine::host::HostOwner,
    handoff::Handoff,
    native_clock::{Installed, Prepared},
};
use core::arch::asm;
use stela_drivers::bus::mmio::owned::{CacheAttribute, Protection};

fn stage<T>(name: &str, result: Result<T, Error>) -> Result<T, Error> {
    if let Err(error) = &result {
        crate::output::arguments(format_args!(
            "CHECK native-mmio REFUSED stage={name} error={error:?}\n"
        ));
    }
    result
}

#[derive(Debug)]
pub(crate) enum ClockError {
    Mapping(Error),
    Work(stela_drivers::platform::work::WorkError),
}
impl core::fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mapping(error) => write!(formatter, "native HPET resource: {error:?}"),
            Self::Work(error) => write!(formatter, "native clock execution: {error:?}"),
        }
    }
}
impl From<Error> for ClockError {
    fn from(error: Error) -> Self {
        Self::Mapping(error)
    }
}
impl From<stela_drivers::platform::work::WorkError> for ClockError {
    fn from(error: stela_drivers::platform::work::WorkError) -> Self {
        Self::Work(error)
    }
}
/// # Safety
/// Explicit owned UP diagnostic on the original native host. An HPET capture
/// selects the whole-controller path; otherwise the existing bounded PM
/// fixture keeps its explicit source-gap limits. Neither admits a Linux owner.
pub(crate) unsafe fn clock(handoff: &Handoff, owner: &mut HostOwner) -> Result<(), ClockError> {
    if handoff.native_resources.cores != 1 || handoff.storage.present {
        return Err(Error::Unavailable.into());
    }
    // SAFETY: original loader capture and physical tables remain held.
    let wire = unsafe { captured(handoff) }?;
    if wire.hpet().is_empty() {
        let prepared = Prepared::from_fadt(wire.fadt())?;
        // SAFETY: the explicit PM diagnostic's original complete <=1second
        // sample-gap contract remains required and unchanged.
        unsafe { crate::native_clock::diagnostic::check(owner, prepared) }?;
        Ok(())
    } else {
        // SAFETY: whole-controller exclusive diagnostic handoff, with
        // no second permission or asynchronous production owner in this boot.
        unsafe { check_native_hpet(handoff, owner) }
    }
}

/// Exercise the production HPET owner, retire it, then reacquire through
/// the same permission for a bounded IRQ/HLT/clock retirement proof. No Runtime
/// or finite RAM-absence capability is published.
/// # Safety
/// The caller supplies the same complete whole-controller diagnostic handoff as
/// check. The original BSP/root and table/backing stay pinned through
/// acknowledged configuration restoration, UC unmap and resource retirement.
unsafe fn check_native_hpet(handoff: &Handoff, owner: &mut HostOwner) -> Result<(), ClockError> {
    // SAFETY: the original immutable loader capture is held by this boot.
    let wire = unsafe { captured(handoff) }?;
    // SAFETY: original BSP before other processors or device owners.
    let source = unsafe { Source::activate(wire, owner, handoff.tsc_hz) }?;
    let identity = owner.root_identity()?;
    // SAFETY: this explicit fixture has exclusive HPET control, no SMM,
    // firmware/native comparator routes or other counter readers/writers.
    let owned = unsafe { source.take_hpet(identity.clone()) }?;
    let mut counter = crate::native_clock::HpetCounter::attach_native_exclusive(owned)?;
    if !alloc::sync::Arc::ptr_eq(counter.identity(), &identity) || counter.owner().is_ok() {
        return Err(Error::InvalidPlatformReply.into());
    }
    let before = counter.read_irq()?;
    let mut after = before;
    for _ in 0..128 {
        after = counter.read_irq()?;
        if after > before {
            break;
        }
    }
    if after <= before {
        return Err(Error::InvalidPlatformReply.into());
    }
    // SAFETY: the same handoff/RootIdentity/native HPET owner is
    // with IF0, active-spin only, before this source is retired.
    match unsafe {
        crate::native_clock::tsc::Candidate::observe(handoff, identity.clone(), &counter)
    } {
        Ok(mut candidate) => {
            candidate
                .recheck()
                .map_err(|_| Error::InvalidPlatformReply)?;
            crate::output::arguments(format_args!(
                "CHECK native-tsc-candidate OBSERVED {:?}; no IRQ, Runtime or continuous-clock grant\n",
                candidate.observation()
            ));
        }
        Err(error) => {
            crate::output::arguments(format_args!(
                "CHECK native-tsc-candidate REFUSED {error:?}; no TSC admission\n"
            ));
            if !matches!(
                error,
                crate::native_clock::tsc::Error::Policy(
                    stela_boot_core::tsc::Error::TscUnavailable
                        | stela_boot_core::tsc::Error::InvariantUnavailable
                        | stela_boot_core::tsc::Error::HypervisorContractRequired
                )
            ) {
                return Err(Error::InvalidPlatformReply.into());
            }
        }
    }
    let base = counter.descriptor().registers().start();
    // SAFETY: this stack frame is the only counter reader, no IRQ/publication
    // exists, and every Source/RootIdentity/controller owner remains live.
    unsafe { counter.retire() }?;
    if counter.read_irq().is_ok() {
        return Err(Error::InvalidPlatformReply.into());
    }
    let status = source.authority().status()?;
    if status.live != 0
        || status.installing != 0
        || status.uncertain != 0
        || status.quarantined != 0
    {
        return Err(Error::UnmapFailed.into());
    }
    drop(counter);
    crate::output::arguments(format_args!(
        "CHECK native-hpet-owner PASS source=production identity=actual base={base:#x} counter=progressed retire=config-restored+UC-unmapped+resource-released; no IRQ, Runtime or RAM-adoption grant\n"
    ));
    // Reuse this same permanent permission after acknowledged first retirement;
    // never activate a competing registry for the subsequent timed proof.
    // SAFETY: same whole-controller owner, no external user was admitted.
    let owned = unsafe { source.take_hpet(identity.clone()) }?;
    let prepared = Prepared::exclusive_native_hpet(owned)?;
    let counter = prepared.hpet_counter().ok_or(Error::Unavailable)?.clone();
    {
        let minimum = prepared.pci_minimum()?;
        let start = counter.read_irq()?;
        minimum.wait_us(20).map_err(|_| Error::Unavailable)?;
        let elapsed = counter.elapsed_bounds(counter.read_irq()?.wrapping_sub(start))?;
        if elapsed.lower_ns < 20_000 {
            return Err(Error::InvalidPlatformReply.into());
        }
    }
    // SAFETY: original Source/RootIdentity, controller, IDT and ARAT
    // delivery stay pinned. This diagnostic creates no production producer.
    unsafe { crate::native_clock::diagnostic::check_native(identity, prepared) }?;
    let mut counter = alloc::sync::Arc::try_unwrap(counter).map_err(|_| Error::ResourceConflict)?;
    // SAFETY: acknowledged clock retirement removed ISR/publication views;
    // unique Arc proves no kept counter reader remains in that graph.
    unsafe { counter.retire() }?;
    let status = source.authority().status()?;
    if status.live != 0
        || status.installing != 0
        || status.uncertain != 0
        || status.quarantined != 0
    {
        return Err(Error::UnmapFailed.into());
    }
    crate::output::arguments(format_args!(
        "CHECK native-hpet-clock PASS source=production identity=immutable IRQ=elapsed idle=HLT guest_mux=elapsed retire=quiet+source-released; no RAM-adoption or production-service grant\n"
    ));
    Ok(())
}

/// Require an already genuine caller-owned notification domain. This checks
/// presence/liveness only; it creates no domain, ownership or history grant.
pub(crate) fn require_notification_owner(
    notification: Option<
        alloc::sync::Arc<dyn stela_drivers::bus::irq::posted_msi::NotificationDomain>,
    >,
) -> Result<alloc::sync::Arc<dyn stela_drivers::bus::irq::posted_msi::NotificationDomain>, Error> {
    let notification = stage(
        "original-notification-owner",
        notification.ok_or(Error::Unavailable),
    )?;
    if let Err(error) = notification.check() {
        crate::output::arguments(format_args!(
            "CHECK native-mmio REFUSED stage=notification-domain error={error:?}\n"
        ));
        return Err(Error::Unavailable);
    }
    Ok(notification)
}

/// # Safety
/// Explicit native diagnostic owns this post-EBS BSP, all controller
/// resources and the complete original HPET/LAPIC source. No firmware, SMM,
/// other CPU or legacy driver owns or accesses HPET control/counter/comparator/
/// decode/route state or IOAPIC/ECAM during the kernel-image epoch. Caller stops the boot immediately afterward, preserving the
/// permanently installed Permission/IRQ/clock's physical root owner.
/// `notification` is the actual retained original CPU/root/controller-format
/// owner for this SAME handoff. Table/map/timed-CPU data never constructs it.
pub(crate) unsafe fn check(
    handoff: &Handoff,
    owner: &mut HostOwner,
    notification: alloc::sync::Arc<dyn stela_drivers::bus::irq::posted_msi::NotificationDomain>,
) -> Result<(), Error> {
    // A checked real input is required even for direct diagnostic callers.
    let notification = require_notification_owner(Some(notification))?;
    if handoff.native_resources.cores != 1 || handoff.storage.present {
        return Err(Error::Unavailable);
    }
    // SAFETY: the caller's contract makes this the post-EBS handoff whose sealed capture this
    // diagnostic owns.
    let wire = stage("capture", unsafe { captured(handoff) })?;
    let root = owner.enter_root().map_err(failed)?;
    // SAFETY: this BSP's root execution is entered and `wire` is that handoff's sealed capture.
    let (source, session) = stage("authority-activate", unsafe {
        ScopedSource::activate(wire, &root)
    })?;
    // SAFETY: diagnostic's complete post-EBS wholeblock handoff excludes
    // firmware/SMM/native comparator/counter/decode/route owners. Original SDT
    // and idle register values alone are not that physical ownership proof.
    let hpet = stage("hpet-wholeblock", unsafe { source.take_hpet() })?;
    let prepared = Prepared::exclusive_hpet(hpet).map_err(failed)?;
    let counter = prepared.hpet_counter().ok_or(Error::Unavailable)?.clone();
    // SAFETY: exact Owner/canonical RootExecution and admitted source.
    let installed = unsafe { Installed::attach(owner, &root, prepared) }.map_err(failed)?;
    // SAFETY: this explicit diagnostic now owns interrupt delivery.
    let execution = unsafe { installed.enter_driver_execution() }.map_err(failed)?;
    let publication = source.root_publication(&root)?;
    // SAFETY: publication and timed Cpu share the canonical
    // RootContext checked by Installed; RootExecution/Installed/DriverExecution
    // remain alive through ALL finite queue/frame/stack/source/publication Drops.
    // This supplies no Linux owner or ExecutionClock/CPU-time accounting grant.
    let stacks =
        unsafe { crate::native_stack_check::run(publication, execution.cpu().map_err(failed)?) }
            .map_err(failed)?;
    crate::output::arguments(format_args!(
        "CHECK native-stack finite=4 actual_rsp={:#x},{:#x} source=retired parent=clear+TLB; no Linux owner or CPU-time grant\n",
        stacks.rsp[0], stacks.rsp[1]
    ));
    // SAFETY: the caller's contract gives this diagnostic every IOAPIC; no firmware, SMM or other
    // CPU touches them.
    let ioapics = stage("ioapic-claim", unsafe { source.claim_ioapics() })?;
    let irq = stage(
        "irq-root-attach",
        // SAFETY: the driver execution owns interrupt delivery and the claimed IOAPICs.
        unsafe {
            crate::native_irq::root::Root::attach(
                &execution,
                source.authority(),
                source.madt(),
                notification,
            )
        }
        .map_err(|error| {
            crate::output::arguments(format_args!(
                "CHECK native-mmio IRQ ROOT REFUSED error={error:?}\n"
            ));
            failed(error)
        }),
    )?;
    // SAFETY: Original MCFG and RootBridge bus membership bind this resource;
    // read one vendor word through the newly installed UC leaf, then retire.
    let (window, ecam) = stage("ecam-claim", unsafe { source.claim_ecam(0, 0..=0) })?;
    let mut mapping = stage(
        "ecam-map",
        source.authority().map(
            ecam.clone(),
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        ),
    )?;
    let cpu = mapping.address(0, 4)?;
    // SAFETY: `cpu` maps the claimed ECAM page uncached and readable for `mapping`'s lifetime.
    let vendor = unsafe { cpu.cast::<u32>().as_ptr().read_volatile() };
    if vendor == 0 || vendor == u32::MAX {
        return Err(Error::MappingFailed);
    }
    let cpu_view = execution.cpu().map_err(failed)?;
    let saved = cpu_view.save_disable().map_err(failed)?;
    let previous: u64;
    // SAFETY: original loader root shares all engine code,
    // stack/GS/IDT and this aperture. No interrupt can run during the switch.
    unsafe {
        asm!("mov {}, cr3", out(reg) previous, options(nomem, nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) handoff.root, options(nostack, preserves_flags));
    }
    let foreign_root_refused = mapping.address(0, 4).is_err();
    // SAFETY: restores this CPU's own root and the flags saved before the switch.
    unsafe {
        asm!("mov cr3, {}", in(reg) previous, options(nostack, preserves_flags));
        cpu_view.restore(saved);
    }
    if !foreign_root_refused {
        return Err(Error::InvalidPlatformReply);
    }
    if !matches!(
        source.authority().map(
            ecam.clone(),
            0,
            PAGE as usize,
            CacheAttribute::WriteCombining,
            Protection::ReadOnly
        ),
        Err(Error::UnsupportedCache)
    ) {
        return Err(Error::InvalidPlatformReply);
    }
    // SAFETY: no pointer from `mapping` is used after its retirement.
    unsafe { mapping.retire() }?;
    if mapping.address(0, 4) != Err(Error::Retired) {
        return Err(Error::InvalidPlatformReply);
    }
    drop(irq);
    source.verify_only_hpet(counter.owner().map_err(failed)?)?;
    let mut reused = source.authority().map(
        ecam,
        0,
        PAGE as usize,
        CacheAttribute::Uncached,
        Protection::ReadOnly,
    )?;
    // SAFETY: `reused` maps the claimed ECAM page uncached and readable while it lives.
    let repeated = unsafe { reused.address(0, 4)?.cast::<u32>().as_ptr().read_volatile() };
    if repeated != vendor {
        return Err(Error::MappingFailed);
    }
    // SAFETY: no pointer from `reused` is used after its retirement.
    unsafe { reused.retire() }?;
    source.verify_only_hpet(counter.owner().map_err(failed)?)?;
    let status = source.authority().status()?;
    if status.live != 1
        || status.installing != 0
        || status.uncertain != 0
        || status.quarantined != 0
    {
        return Err(Error::UnmapFailed);
    }
    crate::output::arguments(format_args!(
        "CHECK native-mmio PASS authority=actual roots=all native_cpus=1 effective_cache=Intel-UC aperture=owned-PTE map=published retire=actual-clear+TLB reuse=readback foreign-root=refused WC=refused clock=HPET64 retained_hpet=1 root_lifetime=kernel-image ioapics={ioapics} MCFG={:#x} buses={}..={} vendor={vendor:#x}; bounded authored diagnostic, Linux and physical hardware unqualified\n",
        window.base, window.start_bus, window.end_bus
    ));
    drop(execution);
    // The permanent IRQ registry keeps timed RootCpu -> real HPET mapping.
    // Preserve the active root/session; no finite HPET/root retirement
    // is claimed. Caller stops immediately with HostOwner still live.
    core::mem::forget(session);
    core::mem::forget(root);
    // Permission and native IRQ registration are permanent. They
    // keep the RootCpu; the caller stops with HostOwner still live.
    // Installed's fields are ManuallyDrop: ending this stack binding preserves
    // the permanent registration and its real root pins without a teardown.
    let _permanent_clock = installed;
    Ok(())
}
