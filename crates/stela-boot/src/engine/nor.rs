//! The guest's NOR flash on a host partition (`--nor SERIAL:GUID`), so
//! NVRAM survives reboots. The image is loaded before the bundle, which
//! hands the kernel its newest valid bank; every sector a committed program
//! or erase changes is stored durably between engine slices, and at the
//! stop.
use crate::output;
use alloc::boxed::Box;
use stela_runtime::{
    boot_bundle::Nvram,
    machine::apple::{
        AppleDevices,
        nor::{Image, persist},
    },
    pc::block::BlockDevice,
};

pub struct HostNor {
    device: Box<dyn BlockDevice>,
}

impl HostNor {
    /// Load the partition's image, initializing a blank one, and the bank
    /// iBoot hands off.
    pub fn open(mut device: Box<dyn BlockDevice>) -> (Self, Image, Nvram) {
        let (image, fresh) = persist::load(&mut *device).unwrap_or_else(|error| {
            output::arguments(format_args!("NOR refusal: {error}\n"));
            output::fatal("the NOR partition could not be loaded")
        });
        let bank = image
            .current_bank()
            .expect("persist::load returns an image with a valid bank");
        let proxy = image.bank(bank).expect("current bank").to_vec();
        output::arguments(format_args!("NOR persistent fresh={fresh} bank={bank}\n"));
        (Self { device }, image, Nvram { bank, proxy })
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
