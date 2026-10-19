//! The machine-state partition (`--nor SERIAL:GUID`): the guest's NOR flash
//! image in its first [`CAPACITY`] bytes, so NVRAM survives reboots, then the
//! SEP's roots and anti-replay store ([`sep_state`]). The image is loaded
//! before the bundle, which hands the kernel its newest valid bank; every
//! sector a committed program or erase changes is stored durably between
//! engine slices, and at the stop.
use crate::output;
use alloc::boxed::Box;
use stela_runtime::{
    boot_bundle::Nvram,
    machine::apple::{
        AppleDevices,
        nor::{CAPACITY, Image, persist},
        sep_state,
    },
    pc::block::{BlockDevice, Shared},
};

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
        (
            Self { device },
            image,
            Nvram { bank, proxy },
            sep_state::Location::Partition { disk, first },
        )
    }

    /// Store the sectors the guest changed. A failed store stops the
    /// machine: NVRAM the guest believes committed must not be lost
    /// silently.
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        for (offset, sector) in devices.nor_dirty() {
            if let Err(error) = persist::store(&mut *self.device, offset, &sector) {
                output::arguments(format_args!("NOR refusal: {error}\n"));
                output::fatal("a NOR sector could not be stored");
            }
        }
    }
}
