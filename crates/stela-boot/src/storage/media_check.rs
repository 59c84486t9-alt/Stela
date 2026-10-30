//! Explicit removable-media fixture diagnostic through kept native USB.
use super::CHECK_BYTES;
use crate::Result;
use crate::output;
use alloc::{boxed::Box, vec, vec::Vec};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use stela_drivers::{
    Clock, Handoff,
    block::{BlockDevice, BlockError},
    bus::{dma::DmaAllocator, pci::Function},
    probe::Devices,
    usb::{
        storage::{UsbDisk, UsbStorage},
        xhci,
    },
};
use stela_runtime::pc::{
    gpt::PartitionDevice,
    storage::{self, Target},
};

const WAIT_US: u64 = 30_000_000;
const POLL_US: u64 = 10_000;

fn failure(stage: &'static str, error: impl core::fmt::Display) -> Refusal {
    output::arguments(format_args!(
        "USB MEDIA FAILED stage={stage} error={error}\n"
    ));
    refuse!("{stage}: {error}", stage, %error)
}
fn no_media(error: &BlockError) -> bool {
    matches!(error, BlockError::Device { status }
        if matches!(status >> 16, 2 | 6) && (status >> 8) & 255 == 0x3a)
}

fn wait_media(
    owner: &mut UsbStorage,
    clock: Clock,
    ready: bool,
    observed: &mut Vec<UsbDisk>,
) -> Result<Vec<UsbDisk>> {
    let deadline = clock.deadline(WAIT_US);
    loop {
        let mut failures = Vec::new();
        let disks = owner
            .rescan(&mut failures)
            .map_err(|error| failure("native media rescan", error))?;
        if let Some((location, error)) = failures.iter().find(|(_, error)| !no_media(error)) {
            observed.extend(disks);
            return Err(failure(
                "media revalidation",
                format_args!("{location}: {error}"),
            ));
        }
        if ready && disks.len() == 1 {
            return Ok(disks);
        }
        if disks.len() > 1 {
            observed.extend(disks);
            return Err(refuse!(
                "USB media diagnostic requires exactly one logical unit"
            ));
        }
        if !ready && disks.is_empty() {
            if failures.iter().any(|(_, error)| no_media(error)) {
                return Ok(disks);
            }
            return Err(refuse!(
                "USB media absence lacks an actual NoMedia response"
            ));
        }
        // Keep all intermediate aliases alive as well; dropping an observed
        // publication is not an acknowledgment of hardware quiescence.
        observed.extend(disks);
        if deadline.passed() {
            return Err(refuse!("USB media stage timed out"));
        }
        clock.delay(POLL_US);
    }
}

fn retired(disk: &mut dyn BlockDevice) -> Result<()> {
    let mut buffer = vec![0xa5; disk.identity().block_size as usize];
    let read = disk.read(0, &mut buffer);
    let flush = disk.flush();
    // This is the existing partition-confined write path, including its own
    // flush/readback. A stale publication must refuse its very first write.
    let check = storage::check(disk, CHECK_BYTES);
    let stale = BlockError::Unsupported("USB storage media publication is stale");
    if read != Err(stale.clone())
        || flush != Err(stale.clone())
        || check != Err(storage::StorageError::Device(stale))
        || buffer.iter().any(|byte| *byte != 0xa5)
    {
        return Err(failure(
            "permanent old-media refusal",
            format_args!("read={read:?} flush={flush:?} check={check:?}"),
        ));
    }
    Ok(())
}

/// # Safety
/// Mapped ECAM/BARs, reserved DMA and exclusive post-EBS native controller
/// ownership must satisfy the ordinary driver probe contract. This diagnostic
/// requires an explicitly selected disposable partition and external stage input.
pub(super) unsafe fn probe_and_rescan(
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
    target: &Target,
) -> Result<Devices> {
    let mut owners = Vec::<xhci::Found>::new();
    let mut retained = Vec::<UsbStorage>::new();
    let mut original = Vec::<UsbDisk>::new();
    let mut replacement = Vec::<UsbDisk>::new();
    let mut observed = Vec::<UsbDisk>::new();
    let mut aliases = Vec::<Box<dyn BlockDevice>>::new();
    let mut partitions = Vec::<PartitionDevice<Box<dyn BlockDevice>>>::new();
    let mut devices = Devices::default();
    let result = (|| {
        for window in &handoff.ecam {
            if !handoff.is_mapped(&window.range()) {
                return Err(refuse!("USB media check requires mapped ECAM"));
            }
            // SAFETY: caller owns the mapped ECAM and native devices.
            for mut function in unsafe { Function::enumerate(window) } {
                if function.class == xhci::CLASS {
                    owners.push(
                        xhci::attach(&mut function, handoff, dma)
                            .map_err(|error| failure("native USB attachment", error))?,
                    );
                }
            }
        }
        if owners
            .iter()
            .map(|found| found.storage.len())
            .sum::<usize>()
            != 1
            || owners.iter().any(|found| !found.disks.is_empty())
        {
            return Err(refuse!(
                "USB media check requires one retained initially empty USB owner"
            ));
        }
        let mut selected = None;
        for found in &owners {
            if let Some((location, error)) =
                found.failures.iter().find(|(_, error)| !no_media(error))
            {
                return Err(failure(
                    "initial USB discovery",
                    format_args!("{location}: {error}"),
                ));
            }
            for device in &found.devices {
                if device.serial.as_deref() != Some(&target.serial) {
                    continue;
                }
                if selected.is_some() {
                    return Err(refuse!("USB media check target serial is ambiguous"));
                }
                let prefix = alloc::format!("{} interface ", device.location);
                selected = found
                    .storage
                    .iter()
                    .find(|owner| owner.location().starts_with(&prefix))
                    .cloned();
                if selected.is_none() {
                    return Err(refuse!(
                        "USB media target has no retained storage interface"
                    ));
                }
            }
        }
        retained.push(selected.ok_or(refuse!("USB media check target was not found"))?);
        let owner = &mut retained[0];
        wait_media(owner, handoff.clock, false, &mut observed)?;
        output::arguments(format_args!("USB MEDIA EMPTY stage=INITIAL nomedia=true\n"));
        output::arguments(format_args!("USB MEDIA WAIT stage=INSERT_A\n"));
        original = wait_media(owner, handoff.clock, true, &mut observed)?;
        let identity = original[0].identity().clone();
        if identity.serial != target.serial {
            return Err(refuse!("USB media insertion changed the selected serial"));
        }
        aliases.extend(
            original
                .drain(..)
                .map(|disk| Box::new(disk) as Box<dyn BlockDevice>),
        );
        partitions.push(
            storage::open(&mut aliases, target)
                .map_err(|error| failure("open medium A first handle", error))?,
        );
        // A second rescan supplies another publication of the same A.
        // open/check alone confine every diagnostic write to the named partition.
        aliases.extend(
            wait_media(owner, handoff.clock, true, &mut observed)?
                .into_iter()
                .map(|disk| Box::new(disk) as Box<dyn BlockDevice>),
        );
        partitions.push(
            storage::open(&mut aliases, target)
                .map_err(|error| failure("open medium A partition", error))?,
        );
        let hash = storage::check(&mut partitions[0], CHECK_BYTES)
            .map_err(|error| failure("check medium A partition", error))?;
        output::arguments(format_args!(
            "USB MEDIA A CHECKED blocks={} block_size={} retained_handles=2 bytes={CHECK_BYTES} sha256={hash}\n",
            identity.blocks, identity.block_size
        ));
        output::arguments(format_args!("USB MEDIA WAIT stage=REMOVE\n"));
        wait_media(owner, handoff.clock, false, &mut observed)?;
        for partition in &mut partitions {
            retired(partition)?;
        }
        output::arguments(format_args!(
            "USB MEDIA EMPTY stage=REMOVE nomedia=true old_handles=2 read_write_flush_refused=true poison_reads_unchanged=true\n"
        ));
        output::arguments(format_args!("USB MEDIA WAIT stage=INSERT_B\n"));
        replacement = wait_media(owner, handoff.clock, true, &mut observed)?;
        let fresh = &mut replacement[0];
        if fresh.identity().serial != identity.serial
            || fresh.identity().location != identity.location
            || fresh.identity().block_size != identity.block_size
            || fresh.identity().blocks == identity.blocks
        {
            return Err(refuse!(
                "USB media replacement did not provide fresh changed geometry"
            ));
        }
        for partition in &mut partitions {
            retired(partition)?;
        }
        let mut first = vec![0; fresh.identity().block_size as usize];
        fresh
            .read(0, &mut first)
            .map_err(|error| failure("read medium B", error))?;
        fresh
            .flush()
            .map_err(|error| failure("flush medium B", error))?;
        output::arguments(format_args!(
            "USB MEDIA CHECKED serial={} location={} old_blocks={} fresh_blocks={} block_size={} permanent_stale=true old_read_refused=true old_flush_refused=true old_a1_read_refused=true old_a1_write_refused=true old_a1_flush_refused=true old_a1_poison_unchanged=true old_a2_read_refused=true old_a2_write_refused=true old_a2_flush_refused=true old_a2_poison_unchanged=true\n",
            identity.serial,
            identity.location,
            identity.blocks,
            fresh.identity().blocks,
            fresh.identity().block_size
        ));
        devices.disks.extend(
            replacement
                .drain(..)
                .map(|disk| Box::new(disk) as Box<dyn BlockDevice>),
        );
        devices.usb_storage.append(&mut retained);
        Ok(())
    })();
    // Keep every class owner and old/new alias for the rest of this diagnostic
    // boot on success and failure. No Drop operation proves DMA retirement.
    core::mem::forget(owners);
    core::mem::forget(retained);
    core::mem::forget(original);
    core::mem::forget(replacement);
    core::mem::forget(observed);
    core::mem::forget(aliases);
    core::mem::forget(partitions);
    result.map(|()| devices)
}
