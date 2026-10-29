//! The machine-state partition (`--nor SERIAL:GUID`): the guest's NOR flash
//! image in its first [`CAPACITY`] bytes, so NVRAM survives reboots, then the
//! SEP's roots and anti-replay store ([`sep_state`]), then, when the
//! partition holds it, the boot log ([`boot_log`]). The image is loaded
//! before the bundle, which hands the kernel its newest valid bank; every
//! sector a committed program or erase changes is stored durably by the
//! host's service, the guest not waiting, and at the stop, as is the
//! pending output.
//!
//! When `--nor` names the `--storage` partition, [`split`] keeps the same
//! layout in that partition's last bytes ([`machine_state`]) and gives the
//! ANS2 model only the rest, so the guest never sees the machine state.
use crate::output;
use alloc::{boxed::Box, collections::BTreeMap, format, vec::Vec};
use stela_drivers::block::{BlockDevice, BlockError, Shared, Submission};
use {
    stela_formats::boot_bundle::Nvram, stela_runtime::machine::apple::AppleDevices,
    stela_runtime::machine::apple::nor::persist, stela_runtime::machine::apple::sep_state,
    stela_runtime::pc::boot_log, stela_runtime::pc::machine_state, stela_soc_data::nor::CAPACITY,
    stela_soc_data::nor::Image,
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
    /// Changed sectors by offset, waiting for the store in progress; a
    /// newer copy of a sector replaces the waiting one.
    waiting: BTreeMap<usize, Vec<u8>>,
    /// The store in progress: its sectors' writes run together, and they
    /// are durable before the next store begins.
    running: Option<Submission>,
}

impl HostNor {
    /// Load the partition's image, initializing a blank one, the bank iBoot
    /// hands off, and where the SEP keeps its state. A partition too small
    /// for both refuses.
    pub fn open(device: Box<dyn BlockDevice>) -> (Self, Image, Nvram, sep_state::Location) {
        let block = u64::from(device.identity().block_size);
        let available = device.identity().blocks.saturating_mul(block);
        let needed = CAPACITY as u64 + stela_formats::machine_state::SEP_BYTES;
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
        let (bank, proxy) = image
            .boot_bank()
            .expect("persist::load returns an identifiable NOR image");
        if image.current_bank().is_err() {
            output::arguments(format_args!(
                "NVRAM recovery: no valid bank; using empty boot variables; flash preserved\n"
            ));
        }
        output::arguments(format_args!("NOR persistent fresh={fresh} bank={bank}\n"));
        open_log(&disk, block, available);
        (
            Self {
                device,
                waiting: BTreeMap::new(),
                running: None,
            },
            image,
            Nvram { bank, proxy },
            sep_state::Location::Partition { disk, first },
        )
    }

    /// The sectors the guest changed, taken from its devices, for
    /// [`Self::store`] to write without them.
    pub fn dirty(devices: &mut AppleDevices) -> Vec<(usize, Vec<u8>)> {
        devices.nor_dirty()
    }

    /// Store the sectors the guest changed, without waiting for the
    /// device: they join the next store, which begins once the one in
    /// progress is durable. A failed store stops the machine: NVRAM the
    /// guest believes committed must not be lost silently.
    pub fn store(&mut self, dirty: Vec<(usize, Vec<u8>)>) {
        self.waiting.extend(dirty);
        self.advance(false);
    }

    /// Complete every store, the caller waiting: at the stop.
    pub fn finish(&mut self) {
        self.advance(true);
    }

    fn advance(&mut self, wait: bool) {
        loop {
            if let Some(running) = self.running.as_mut() {
                match running.poll(&mut *self.device) {
                    None if wait => {
                        core::hint::spin_loop();
                        continue;
                    }
                    None => return,
                    Some(Err(error)) => {
                        output::arguments(format_args!(
                            "NOR refusal: NOR partition store: {error}\n"
                        ));
                        output::fatal("a NOR sector could not be stored");
                    }
                    Some(Ok(_)) => self.running = None,
                }
            }
            if self.waiting.is_empty() {
                return;
            }
            let identity = self.device.identity();
            let store = core::mem::take(&mut self.waiting)
                .into_iter()
                .map(|(offset, sector)| persist::request(identity, offset, sector))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|requests| {
                    Submission::batch(requests, identity).map_err(|error| format!("{error}"))
                });
            match store {
                Ok(store) => self.running = Some(store),
                Err(error) => {
                    output::arguments(format_args!("NOR refusal: {error}\n"));
                    output::fatal("a NOR sector could not be stored");
                }
            }
        }
    }
}

/// Open the boot log after the SEP's state and hand it to the output, when
/// the partition holds the region; otherwise say why there is none. Returns
/// whether the log is open.
pub(crate) fn open_log(disk: &Shared, block: u64, available: u64) -> bool {
    if available < boot_log::PARTITION_BYTES {
        output::arguments(format_args!(
            "BOOT LOG off: the machine-state partition holds {available:#x} bytes; the log needs {:#x}\n",
            boot_log::PARTITION_BYTES
        ));
        return false;
    }
    if !boot_log::OFFSET.is_multiple_of(block) || !boot_log::LOG_BYTES.is_multiple_of(block) {
        output::arguments(format_args!(
            "BOOT LOG off: {block}-byte blocks do not divide the log region\n"
        ));
        return false;
    }
    let mut device: Box<dyn BlockDevice> = Box::new(
        disk.window(boot_log::OFFSET / block, boot_log::LOG_BYTES / block)
            .expect("the partition holds the log region"),
    );
    let writer = match boot_log::Writer::open(&mut *device) {
        Ok(writer) => writer,
        Err(error @ (BlockError::Unsupported(_) | BlockError::ReadOnly)) => {
            output::arguments(format_args!("BOOT LOG off: {error}\n"));
            return false;
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
    match output::add_log(writer, device, output::Log::Machine) {
        Ok(()) => true,
        Err(error @ output::Unopened::Store(_)) => {
            output::arguments(format_args!("BOOT LOG refusal: {error}\n"));
            output::fatal("the boot log could not be stored")
        }
        // The disk took the writes and keeps none: NVRAM will not persist
        // either. The boot goes on, so the screen shows how far it gets.
        Err(error) => {
            output::arguments(format_args!("BOOT LOG unkept: {error}\n"));
            crate::status::warn(&format!("the disk does not keep its writes: {error}"));
            false
        }
    }
}
