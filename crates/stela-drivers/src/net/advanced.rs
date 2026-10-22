//! Intel advanced descriptors with one buffer per frame, as the igb and igc
//! queues use them (82575 and I225 datasheets §7.1–7.2; Linux
//! `e1000_82575.h`, `igb.h` and `igc_base.h`).
use super::ring::{BUFFER, DESCRIPTOR, DESCRIPTORS, Ring};
use crate::{Clock, bus::dma::DmaBuffer};
use core::sync::atomic::{Ordering, fence};

/// RXDCTL and TXDCTL queue enable.
pub(crate) const QUEUE_ENABLE: u32 = 1 << 25;
/// Prefetch 8, host 8 and write back every receive descriptor at once;
/// transmit descriptors are written back on their RS bit.
pub(crate) const RXDCTL_THRESHOLDS: u32 = 8 | 8 << 8 | 1 << 16;
pub(crate) const TXDCTL_THRESHOLDS: u32 = 8 | 1 << 8;
/// SRRCTL: the packet buffer in 1 KiB units, one buffer per descriptor.
pub(crate) const SRRCTL_ONE_BUFFER: u32 = (BUFFER >> 10) as u32 | 1 << 25;
/// How long a queue may take to report itself enabled or stopped.
pub(crate) const QUEUE_WAIT_US: u64 = 20_000;

pub(crate) const RX_DD: u32 = 1 << 0;
pub(crate) const RX_EOP: u32 = 1 << 1;
const TX_DD: u32 = 1 << 0;
const TX_DTYP_DATA: u32 = 0x3 << 20;
const TX_EOP: u32 = 1 << 24;
const TX_IFCS: u32 = 1 << 25;
const TX_RS: u32 = 1 << 27;
const TX_DEXT: u32 = 1 << 29;
const TX_PAYLEN_SHIFT: u32 = 14;

const _: () = assert!((DESCRIPTORS * DESCRIPTOR).is_multiple_of(128));

/// A data descriptor's command word and status for one frame in one buffer,
/// with the CRC inserted and a write-back requested.
pub(crate) fn transmit_words(length: usize) -> (u32, u32) {
    let length = length as u32;
    (
        TX_DTYP_DATA | TX_DEXT | TX_IFCS | TX_EOP | TX_RS | length,
        length << TX_PAYLEN_SHIFT,
    )
}

/// Whether the controller wrote back the transmit descriptor at `base`.
pub(crate) fn transmitted(descriptors: &DmaBuffer, base: usize) -> bool {
    descriptors.read::<u32>(base + 12) & TX_DD != 0
}

/// Queue one frame in `ring`'s next descriptor; the caller rings TDT.
pub(crate) fn queue_frame(ring: &mut Ring, frame: &[u8], length: usize) {
    let index = ring.advance();
    let buffer = ring.buffer(index);
    buffer[..length].fill(0);
    buffer[..frame.len()].copy_from_slice(frame);
    let (command, status) = transmit_words(length);
    let base = index * DESCRIPTOR;
    let address = ring.address(index);
    ring.descriptors.write(base, address);
    ring.descriptors.write(base + 8, command);
    ring.descriptors.write(base + 12, status);
    fence(Ordering::SeqCst);
}

/// Hand receive descriptor `index` its buffer; the zero header address also
/// clears the previous write-back's status.
pub(crate) fn offer_receive(ring: &mut Ring, index: usize) {
    let address = ring.address(index);
    ring.descriptors.write(index * DESCRIPTOR, address);
    ring.descriptors.write(index * DESCRIPTOR + 8, 0u64);
}

/// One transmit queue's registers.
pub(crate) struct TransmitQueue {
    pub(crate) head: usize,
    pub(crate) tail: usize,
    pub(crate) control: usize,
}

impl TransmitQueue {
    /// Stop the queue, discard every queued descriptor and start it empty:
    /// Linux resets the controller for transmit work a lost link strands.
    pub(crate) fn flush(
        &self,
        ring: &mut Ring,
        clock: Clock,
        read: impl Fn(usize) -> u32,
        write: impl Fn(usize, u32),
    ) -> bool {
        let control = read(self.control);
        write(self.control, control & !QUEUE_ENABLE);
        if !clock.wait(QUEUE_WAIT_US, || read(self.control) & QUEUE_ENABLE == 0) {
            return false;
        }
        write(self.head, 0);
        write(self.tail, 0);
        ring.reset();
        write(self.control, control | QUEUE_ENABLE);
        clock.wait(QUEUE_WAIT_US, || read(self.control) & QUEUE_ENABLE != 0)
    }
}
