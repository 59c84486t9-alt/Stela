//! Durable ANS2 namespace erases. Re-creating a namespace erases it at
//! once for the guest (an in-memory erased-block map in the runtime's ANS
//! medium); the host's bytes are zeroed here, a bounded amount between
//! engine slices and the rest at the stop, so blocks the guest never
//! rewrote cannot come back as stale data on the next boot. The work is
//! host time, which the guest's clock excludes, so no command waits on it.
use crate::output;
use stela_runtime::machine::apple::AppleDevices;

/// 4 KiB blocks zeroed after each slice: 4 MiB, four of the backing's
/// largest transfers and one flush.
const SLICE_BLOCKS: u64 = 1024;
/// 4 KiB blocks per step at the stop, each flushed and reported: 1 GiB.
const STOP_BLOCKS: u64 = 1 << 18;

#[derive(Default)]
pub struct HostErase {
    /// Blocks pending after the last call, to report an erase's start
    /// and completion once each.
    pending: u64,
}

impl HostErase {
    /// Zero up to [`SLICE_BLOCKS`] erased blocks.
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        self.step(devices, SLICE_BLOCKS);
    }

    /// Zero every erased block before the machine stops. A host stop that
    /// does not return through the run loop leaves the rest stale.
    pub fn finish(&mut self, devices: &mut AppleDevices) {
        while self.step(devices, STOP_BLOCKS) != 0 {
            output::arguments(format_args!(
                "ANS erase at stop pending_blocks={}\n",
                self.pending
            ));
        }
    }

    /// A failed store stops the machine: an erase the guest saw complete
    /// must not be lost silently.
    fn step(&mut self, devices: &mut AppleDevices, blocks: u64) -> u64 {
        // Only zeroing lowers the count, so a rise is a new erase.
        let total = devices.ans_erase_pending();
        if total > self.pending {
            output::arguments(format_args!("ANS erase pending_blocks={total}\n"));
        }
        let pending = devices.ans_zero_erased(blocks).unwrap_or_else(|error| {
            output::arguments(format_args!("ANS erase refusal: {error}\n"));
            output::fatal("an erased ANS namespace block could not be zeroed")
        });
        if pending == 0 && total != 0 {
            output::arguments(format_args!("ANS erase durable\n"));
        }
        self.pending = pending;
        pending
    }
}
