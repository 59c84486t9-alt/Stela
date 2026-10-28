//! Explicit native UAS reset diagnostic before block-device type erasure.
//! No alternate enumeration or recovery behavior is enabled in normal boots.
use crate::output;
use alloc::{boxed::Box, vec, vec::Vec};
use stela_drivers::{
    Handoff,
    block::BlockDevice,
    bus::{dma::DmaAllocator, pci::Function},
    probe::Devices,
    usb::{storage::UsbDisk, xhci},
};
use stela_runtime::pc::storage::Target;

fn failure(stage: &'static str, error: impl core::fmt::Display) -> &'static str {
    output::arguments(format_args!(
        "USB RESET FAILED stage={stage} error={error}\n"
    ));
    stage
}

/// # Safety
/// Actual mapped ECAM, BARs, reserved DMA and exclusive post-EBS controller
/// ownership must satisfy the ordinary native driver probe contract.
pub(super) unsafe fn probe_and_reset(
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
    target: &Target,
) -> Result<Devices, &'static str> {
    let mut owners = Vec::<xhci::Found>::new();
    let mut replacement = Vec::<UsbDisk>::new();
    let mut fresh_storage = Vec::new();
    let mut devices = Devices::default();
    let result = (|| {
        for window in &handoff.ecam {
            if !handoff.is_mapped(&window.range()) {
                return Err("USB reset check requires mapped ECAM");
            }
            // SAFETY: caller owns the actual mapped ECAM and native devices.
            for mut function in unsafe { Function::enumerate(window) } {
                if function.class == xhci::CLASS {
                    owners.push(
                        xhci::attach(&mut function, handoff, dma)
                            .map_err(|error| failure("native USB attachment", error))?,
                    );
                }
            }
        }
        // Establish exact uniqueness before a physical device is reset.
        let mut selected = None;
        for (controller, found) in owners.iter().enumerate() {
            for (disk, device) in found.disks.iter().enumerate() {
                if device.identity().serial == target.serial
                    && selected.replace((controller, disk)).is_some()
                {
                    return Err("USB reset check target serial is ambiguous");
                }
            }
        }
        let (controller, disk) = selected.ok_or("USB reset check target was not found")?;
        let original = &mut owners[controller].disks[disk];
        let identity = original.identity().clone();
        let mut before = vec![0; identity.block_size as usize];
        original
            .read(0, &mut before)
            .map_err(|error| failure("read before USB reset", error))?;
        let mut failures = Vec::new();
        let (owner, disks) = original
            .reset_and_rebind_retained(dma, &mut failures)
            .map_err(|error| failure("native UAS reset and rebind", error))?;
        fresh_storage.push(owner);
        replacement = disks;
        for (location, error) in &failures {
            output::arguments(format_args!("USB RESET FAILED {location}: {error}\n"));
        }
        if !failures.is_empty() {
            return Err("USB reset fresh SCSI discovery failed");
        }
        // The original object remains alive. Its old epoch must never submit
        // to a replacement slot, even when the hardware offered that ID again.
        let mut retired_buffer = vec![0xa5; before.len()];
        if original.read(0, &mut retired_buffer).is_ok()
            || original.flush().is_ok()
            || retired_buffer.iter().any(|byte| *byte != 0xa5)
        {
            return Err("USB reset allowed the retired disk to perform I/O");
        }
        let mut matching = replacement.iter_mut().filter(|device| {
            device.identity().serial == identity.serial
                && device.identity().location == identity.location
        });
        let fresh = matching
            .next()
            .ok_or("USB reset lost the selected logical unit")?;
        if matching.next().is_some() {
            return Err("USB reset produced ambiguous replacement logical units");
        }
        if fresh.identity().blocks != identity.blocks
            || fresh.identity().block_size != identity.block_size
        {
            return Err("USB reset diagnostic media geometry changed");
        }
        let mut after = vec![0; fresh.identity().block_size as usize];
        fresh
            .read(0, &mut after)
            .map_err(|error| failure("read after USB reset", error))?;
        if before != after {
            return Err("USB reset changed the first disk block");
        }
        fresh
            .flush()
            .map_err(|error| failure("flush after USB reset", error))?;
        output::arguments(format_args!(
            "USB RESET CHECKED serial={} location={} blocks={} block_size={} old_read_refused=true old_flush_refused=true\n",
            identity.serial,
            identity.location,
            fresh.identity().blocks,
            fresh.identity().block_size
        ));
        devices.disks.extend(
            replacement
                .drain(..)
                .map(|disk| Box::new(disk) as Box<dyn BlockDevice>),
        );
        devices.usb_storage.append(&mut fresh_storage);
        Ok(())
    })();
    // Explicit boot-lifetime fixture retention, including every failure exit:
    // other attached class owners and quarantined/replacement DMA must not be
    // destroyed while hardware ownership could remain unresolved.
    core::mem::forget(owners);
    core::mem::forget(replacement);
    core::mem::forget(fresh_storage);
    result.map(|()| devices)
}
