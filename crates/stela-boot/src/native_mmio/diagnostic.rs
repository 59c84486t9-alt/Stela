//! Actual page-table/UC/IOAPIC source composition. This bounded diagnostic
//! publishes no Linux driver and qualifies no physical hardware profile.
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

/// # Safety
/// Explicit native diagnostic owns this actual post-EBS BSP, all controller
/// resources and fixed PM/LAPIC source. The trusted execution fixture guarantees
/// subsecond PM sampling gaps. No firmware/SMM/other CPU or legacy driver uses
/// IOAPIC/ECAM. Caller stops the boot immediately afterward, preserving the
/// permanently installed Authority/IRQ/clock's physical root owner.
pub(crate) unsafe fn check(handoff: &Handoff, owner: &mut HostOwner) -> Result<(), Error> {
    if handoff.native_resources.cores != 1 || handoff.storage.present {
        return Err(Error::Unavailable);
    }
    let wire = stage("capture", unsafe { captured(handoff) })?;
    let prepared = Prepared::from_fadt(wire.fadt()).map_err(failed)?;
    let prepared = unsafe { prepared.qualify_bounded(1_000_000_000) }.map_err(failed)?;
    let installed = unsafe { Installed::attach(owner, prepared) }.map_err(failed)?;
    let execution = unsafe { installed.enter_driver_execution() }.map_err(failed)?;
    let roots = stage("root-inventory", owner.mmio_roots(&execution, handoff))?;
    let (source, session) = stage("authority-activate", unsafe {
        Source::activate(wire, roots, &execution)
    })?;
    let ioapics = stage("ioapic-claim", unsafe { source.claim_ioapics() })?;
    let irq = stage(
        "irq-root-attach",
        unsafe {
            crate::native_irq::root::Root::attach(&execution, source.authority(), source.madt())
        }
        .map_err(|error| {
            crate::output::arguments(format_args!(
                "CHECK native-mmio IRQ ROOT REFUSED error={error:?}\n"
            ));
            failed(error)
        }),
    )?;
    // Actual original MCFG and RootBridge bus membership bind this resource;
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
    let vendor = unsafe { cpu.cast::<u32>().as_ptr().read_volatile() };
    if vendor == 0 || vendor == u32::MAX {
        return Err(Error::MappingFailed);
    }
    let cpu_view = execution.cpu().map_err(failed)?;
    let saved = cpu_view.save_disable().map_err(failed)?;
    let previous: u64;
    // SAFETY: exact retained original loader root shares all engine code,
    // stack/GS/IDT and this aperture. No interrupt can run during the switch.
    unsafe {
        asm!("mov {}, cr3", out(reg) previous, options(nomem, nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) handoff.root, options(nostack, preserves_flags));
    }
    let foreign_root_refused = mapping.address(0, 4).is_err();
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
    unsafe { mapping.retire() }?;
    if mapping.address(0, 4) != Err(Error::Retired) {
        return Err(Error::InvalidPlatformReply);
    }
    drop(irq);
    source.verify_empty()?;
    let mut reused = source.authority().map(
        ecam,
        0,
        PAGE as usize,
        CacheAttribute::Uncached,
        Protection::ReadOnly,
    )?;
    let repeated = unsafe { reused.address(0, 4)?.cast::<u32>().as_ptr().read_volatile() };
    if repeated != vendor {
        return Err(Error::MappingFailed);
    }
    unsafe { reused.retire() }?;
    source.verify_empty()?;
    let status = source.authority().status()?;
    if status.live != 0
        || status.installing != 0
        || status.uncertain != 0
        || status.quarantined != 0
    {
        return Err(Error::UnmapFailed);
    }
    crate::output::arguments(format_args!(
        "CHECK native-mmio PASS authority=actual roots=all native_cpus=1 effective_cache=Intel-UC aperture=owned-PTE map=published retire=actual-clear+TLB reuse=readback foreign-root=refused WC=refused ioapics={ioapics} MCFG={:#x} buses={}..={} vendor={vendor:#x}; bounded authored diagnostic, Linux and physical hardware unqualified\n",
        window.base, window.start_bus, window.end_bus
    ));
    drop(session);
    drop(execution);
    // Authority and native IRQ registration are deliberately permanent. They
    // retain the actual RootCpu; the caller stops with HostOwner still live.
    // Installed's fields are ManuallyDrop: ending this stack binding preserves
    // the permanent registration and its real root pins without a teardown.
    let _permanent_clock = installed;
    Ok(())
}
