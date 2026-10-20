//! The machine-state partition (`--nor SERIAL:GUID`): the guest's NOR flash
//! image in its first [`CAPACITY`] bytes, so NVRAM survives reboots, then the
//! SEP's roots and anti-replay store ([`sep_state`]), then, when the
//! partition holds it, the boot log ([`boot_log`]). The image is loaded
//! before the bundle, which hands the kernel its newest valid bank; every
//! sector a committed program or erase changes is stored durably between
//! engine slices, and at the stop, as is the pending output.
//!
//! When `--nor` names the `--storage` partition, [`split`] keeps the same
//! layout in that partition's last bytes ([`machine_state`]) and gives the
//! ANS2 model only the rest, so the guest never sees the machine state.
use crate::output;
use alloc::boxed::Box;
use stela_runtime::{
    boot_bundle::Nvram,
    machine::apple::{
        AppleDevices,
        nor::{CAPACITY, Image, persist},
        sep_state,
    },
    pc::{
        block::{BlockDevice, BlockError, Shared},
        boot_log, machine_state,
    },
};

/// Split the Apple region `partition` into the guest's ANS2 namespace and
/// the machine state in its tail. A partition too small for both, or with
/// blocks that do not divide the alignment, refuses.
pub fn split(partition: Box<dyn BlockDevice>) -> (Box<dyn BlockDevice>, Box<dyn BlockDevice>) {
    let (namespace, state, layout) =
        machine_state::split_device(partition).unwrap_or_else(|error| {
            output::arguments(format_args!("MACHINE STATE refusal: {error}\n"));
            output::fatal("the --storage partition cannot also hold the machine state")
        });
    output::arguments(format_args!(
        "MACHINE STATE in the target's last {:#x} bytes (from {:#x}); the ANS2 namespace holds \
         {:#x}\n",
        layout.state_bytes, layout.namespace_bytes, layout.namespace_bytes
    ));
    (Box::new(namespace), Box::new(state))
}

pub struct HostNor {
    device: Box<dyn BlockDevice>,
}

impl HostNor {
    /// Load the partition's image, initializing a blank one, the bank iBoot
    /// hands off, and where the SEP keeps its state. A partition too small
    /// for both refuses.
    pub fn open(device: Box<dyn BlockDevice>) -> (Self, Image, Nvram, sep_state::Location) {
        let block = u64::from(device.identity().block_size);
        let available = device.identity().blocks.saturating_mul(block);
        let needed = CAPACITY as u64 + sep_state::BYTES;
        if block == 0 || !(CAPACITY as u64).is_multiple_of(block) || available < needed {
            output::arguments(format_args!(
                "NOR refusal: the partition holds {available:#x} bytes in {block}-byte blocks; the NOR image and SEP state need {needed:#x}\n"
            ));
            output::fatal("the machine-state partition is too small");
        }
        let disk = Shared::new(device);
        let first = CAPACITY as u64 / block;
        let mut device: Box<dyn BlockDevice> = Box::new(
            disk.window(0, first)
                .expect("the partition holds the NOR image"),
        );
        let (image, fresh) = persist::load(&mut *device).unwrap_or_else(|error| {
            output::arguments(format_args!("NOR refusal: {error}\n"));
            output::fatal("the NOR partition could not be loaded")
        });
        let bank = image
            .current_bank()
            .expect("persist::load returns an image with a valid bank");
        let proxy = image.bank(bank).expect("current bank").to_vec();
        output::arguments(format_args!("NOR persistent fresh={fresh} bank={bank}\n"));
        open_log(&disk, block, available);
        (
            Self { device },
            image,
            Nvram { bank, proxy },
            sep_state::Location::Partition { disk, first },
        )
    }

    /// Store the sectors the guest changed and the pending output. A failed
    /// store stops the machine: NVRAM the guest believes committed must not
    /// be lost silently.
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        self.store_sectors(devices);
        output::flush_log();
    }

    fn store_sectors(&mut self, devices: &mut AppleDevices) {
        for (offset, sector) in devices.nor_dirty() {
            if let Err(error) = persist::store(&mut *self.device, offset, &sector) {
                output::arguments(format_args!("NOR refusal: {error}\n"));
                output::fatal("a NOR sector could not be stored");
            }
        }
    }
}

/// Open the boot log after the SEP's state and hand it to the output, when
/// the partition holds the region; otherwise say why there is none.
fn open_log(disk: &Shared, block: u64, available: u64) {
    if available < boot_log::PARTITION_BYTES {
        output::arguments(format_args!(
            "BOOT LOG off: the machine-state partition holds {available:#x} bytes; the log needs {:#x}\n",
            boot_log::PARTITION_BYTES
        ));
        return;
    }
    if !boot_log::OFFSET.is_multiple_of(block) || !boot_log::LOG_BYTES.is_multiple_of(block) {
        output::arguments(format_args!(
            "BOOT LOG off: {block}-byte blocks do not divide the log region\n"
        ));
        return;
    }
    let mut device: Box<dyn BlockDevice> = Box::new(
        disk.window(boot_log::OFFSET / block, boot_log::LOG_BYTES / block)
            .expect("the partition holds the log region"),
    );
    let writer = match boot_log::Writer::open(&mut *device) {
        Ok(writer) => writer,
        Err(error @ (BlockError::Unsupported(_) | BlockError::ReadOnly)) => {
            output::arguments(format_args!("BOOT LOG off: {error}\n"));
            return;
        }
        Err(error) => {
            output::arguments(format_args!("BOOT LOG refusal: {error}\n"));
            output::fatal("the boot log could not be opened")
        }
    };
    if let Some(reason) = writer.fresh() {
        output::arguments(format_args!("BOOT LOG fresh: {reason}\n"));
    }
    output::arguments(format_args!(
        "BOOT LOG boot={} offset={:#x} bytes={:#x} head={:#x}\n",
        writer.boots(),
        boot_log::OFFSET,
        boot_log::LOG_BYTES,
        writer.head()
    ));
    output::install_log(writer, device);
}
