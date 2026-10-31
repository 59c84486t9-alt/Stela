// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! One live scheduler queue, as `iwl_txq_gen2_tx` fills it and
//! `iwl_pcie_reclaim` empties it: a frame takes the next descriptor, its
//! first 20 bytes the slot's coherent TB0 and the rest one mapped buffer, its
//! byte count the table entry the scheduler reads, and the write pointer
//! tells the device. A TX response names the first index it has not finished.
use super::{Encoded, Error as FrameError, Prepared, queue::NativeMemory};
use crate::{
    bus::dma::{
        mapping::{Direction, DmaDomain},
        memory::PageSource,
    },
    wifi::intel::{command::FIRST_TB_BYTES, context::Region, dma::Chunk, firmware::Family},
};
use alloc::{sync::Arc, vec::Vec};

/// One frame's mapped remainder: TB1, then the payload.
const BUFFER_BYTES: usize = 4096;
/// `HBUS_TARG_WRPTR`.
pub(in crate::wifi::intel) const WRITE_POINTER: u32 = 0x460;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Frame(FrameError),
    Queue(super::queue::Error),
    Dma(crate::wifi::intel::dma::Error),
    /// Every descriptor is in flight; the frame waits for a TX response.
    Full,
    /// The frame does not fit one mapped buffer.
    FrameLength,
    /// The firmware named an index outside what is in flight.
    Reclaim {
        read: u16,
        write: u16,
        next: u16,
    },
}

/// A queue the device reads and the frames it has not finished.
pub(in crate::wifi::intel) struct Ring {
    memory: NativeMemory,
    domain: Arc<dyn DmaDomain>,
    family: Family,
    queue: u16,
    /// Unmasked pointers, which wrap at `iwl_txq_inc_wrap`'s queue size.
    read: u16,
    write: u16,
    slots: Vec<Option<Chunk>>,
    pool: Vec<Chunk>,
}

impl Ring {
    pub(in crate::wifi::intel) fn new(
        memory: NativeMemory,
        domain: Arc<dyn DmaDomain>,
        family: Family,
        queue: u16,
        write_pointer: u16,
    ) -> Self {
        let slots = (0..memory.slots()).map(|_| None).collect();
        Self {
            memory,
            domain,
            family,
            queue,
            read: write_pointer,
            write: write_pointer,
            slots,
            pool: Vec::new(),
        }
    }

    pub(in crate::wifi::intel) fn queue(&self) -> u16 {
        self.queue
    }

    fn next(&self, pointer: u16) -> u16 {
        if self.family == Family::Ax200 {
            pointer.wrapping_add(1) & 255
        } else {
            pointer.wrapping_add(1)
        }
    }

    fn distance(&self, from: u16, to: u16) -> u16 {
        let distance = to.wrapping_sub(from);
        if self.family == Family::Ax200 {
            distance & 255
        } else {
            distance
        }
    }

    fn slot(&self, pointer: u16) -> usize {
        usize::from(pointer) & (self.slots.len() - 1)
    }

    /// The frames the device has not finished.
    pub(in crate::wifi::intel) fn used(&self) -> u16 {
        self.distance(self.read, self.write)
    }

    /// `iwl_txq_space`: a queue as long as the pointer range keeps one back.
    pub(in crate::wifi::intel) fn space(&self) -> u16 {
        let window = self.slots.len() as u16;
        let limit = if self.family == Family::Ax200 && window == 256 {
            255
        } else {
            window
        };
        limit.saturating_sub(self.used())
    }

    /// Fill the next descriptor with `frame`, returning the value that
    /// publishes it through [`WRITE_POINTER`].
    ///
    /// # Safety
    /// The firmware accepted this queue, its domain still maps it, and the
    /// caller writes the returned value before anything else moves the queue.
    pub(in crate::wifi::intel) unsafe fn publish(
        &mut self,
        frame: &Prepared,
        source: &dyn PageSource,
    ) -> Result<u32, Error> {
        if self.space() == 0 {
            return Err(Error::Full);
        }
        let index = self.write;
        let slot = self.slot(index);
        let encoded = frame.encode(self.queue, index).map_err(Error::Frame)?;
        let mut buffer = match self.pool.pop() {
            Some(buffer) => buffer,
            None => Chunk::allocate(
                source,
                self.domain.clone(),
                &[0; BUFFER_BYTES],
                Direction::ToDevice,
            )
            .map_err(Error::Dma)?,
        };
        // SAFETY: this descriptor is empty, so neither the pooled buffer nor
        // its TB0 slot is in the device's hands.
        let (first, second, payload) = unsafe { self.fill(&encoded, slot, &buffer) }?;
        let (tfd, byte_count) = encoded.tfd(first, second, payload).map_err(Error::Frame)?;
        buffer.expose();
        self.slots[slot] = Some(buffer);
        // SAFETY: as above; the descriptor is published after this returns.
        unsafe { self.memory.write_descriptor(slot, tfd.bytes(), byte_count) }
            .map_err(Error::Queue)?;
        self.write = self.next(index);
        Ok(u32::from(self.write) | u32::from(self.queue) << 16)
    }

    /// Copy `encoded` to TB0 and `buffer`, returning their regions.
    unsafe fn fill(
        &self,
        encoded: &Encoded,
        slot: usize,
        buffer: &Chunk,
    ) -> Result<(Region, Region, Option<Region>), Error> {
        let (second, payload) = (encoded.second_tb(), encoded.payload());
        if second.len() + payload.len() > BUFFER_BYTES {
            return Err(Error::FrameLength);
        }
        let base = buffer.region().address;
        let mut bytes = Vec::with_capacity(second.len() + payload.len());
        bytes.extend_from_slice(second);
        bytes.extend_from_slice(payload);
        // SAFETY: the caller's empty descriptor owns the buffer and slot.
        unsafe {
            buffer.write_owned(0, &bytes).map_err(Error::Dma)?;
            self.memory
                .write_first(slot, encoded.first_tb())
                .map_err(Error::Queue)?;
        }
        Ok((
            Region {
                address: self.memory.first(slot),
                bytes: FIRST_TB_BYTES,
            },
            Region {
                address: base,
                bytes: second.len(),
            },
            (!payload.is_empty()).then_some(Region {
                address: base + second.len() as u64,
                bytes: payload.len(),
            }),
        ))
    }

    /// `iwl_pcie_reclaim`: the device finished every frame before `next`.
    /// Returns how many.
    ///
    /// # Safety
    /// `next` comes from this queue's TX response or flush answer, which
    /// ends the device's use of each frame before it.
    pub(in crate::wifi::intel) unsafe fn reclaim(&mut self, next: u16) -> Result<u16, Error> {
        let (read, write) = (self.read, self.write);
        let finished = self.distance(read, next);
        if finished > self.used() {
            return Err(Error::Reclaim { read, write, next });
        }
        for _ in 0..finished {
            let slot = self.slot(self.read);
            let buffer = self.slots[slot]
                .take()
                .ok_or(Error::Reclaim { read, write, next })?;
            // SAFETY: the caller's response ended the device's use of the
            // slot; the invalid descriptor replaces its pointers.
            unsafe { self.memory.invalidate(slot) }.map_err(Error::Queue)?;
            self.pool.push(buffer);
            self.read = self.next(self.read);
        }
        Ok(finished)
    }

    /// Give back the queue's memory once it is empty and the firmware has
    /// removed it.
    ///
    /// # Safety
    /// The firmware acknowledged the scheduler's removal of this queue.
    pub(in crate::wifi::intel) unsafe fn release(&mut self) -> Result<(), Error> {
        for mut buffer in self.pool.drain(..) {
            // SAFETY: the caller's removal ended all device access.
            unsafe { buffer.release() }
                .map_err(|error| Error::Dma(crate::wifi::intel::dma::Error::Dma(error)))?;
        }
        // SAFETY: as above.
        unsafe { self.memory.release() }.map_err(Error::Queue)
    }

    pub(in crate::wifi::intel) fn uncertain(&self) -> bool {
        self.memory.uncertain() || self.used() != 0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        Parameters,
        tests::{firmware, rows},
    };
    use super::*;
    use crate::wifi::intel::{
        dma::tests::{Domain, Source},
        firmware::Firmware,
    };

    fn frame(fw: &Firmware<'_>, family: Family, bytes: usize) -> Prepared {
        let mut mpdu = alloc::vec![0x5a; bytes];
        mpdu[..2].copy_from_slice(&0x0188u16.to_le_bytes());
        mpdu[22] = 0;
        let parameters = Parameters {
            station_authorized: Some(true),
            force_host_rate: false,
            host_rate: super::super::LegacyRate::Ofdm6,
            host_antenna: 1,
            firmware_encryption: false,
        };
        Prepared::prepare(fw, family, &mpdu, parameters).unwrap()
    }

    fn ring(family: Family, slots: u16, write: u16) -> (Ring, Source, Arc<Domain>, Vec<u8>) {
        let mut table = rows(family).to_vec();
        table.push([0x17, 5, 3, 2]);
        let bytes = firmware(&table);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let fw = Firmware::parse(&bytes).unwrap();
        let mut memory =
            NativeMemory::prepare(&fw, family, slots, &source, domain.clone()).unwrap();
        // SAFETY: fresh model memory no device reaches.
        unsafe { memory.expose() }.unwrap();
        let ring = Ring::new(memory, domain.clone(), family, 7, write);
        (ring, source, domain, bytes)
    }

    #[test]
    fn a_frame_takes_a_descriptor_its_byte_count_and_the_doorbell() {
        for (family, count) in [(Family::Ax200, 25u16), (Family::Ax210, 100)] {
            let (mut ring, source, _domain, bytes) = ring(family, 16, 3);
            let fw = Firmware::parse(&bytes).unwrap();
            // SAFETY: the model queue is live.
            let doorbell = unsafe { ring.publish(&frame(&fw, family, 100), &source) }.unwrap();
            assert_eq!(doorbell, 4 | 7 << 16);
            assert_eq!(ring.used(), 1);
            assert_eq!(ring.space(), 15);
            assert_eq!(ring.memory.byte_count(3), count);
            let tfd = ring.memory.descriptor(3);
            assert_eq!(u16::from_le_bytes([tfd[0], tfd[1]]), 3);
            assert_eq!(
                u64::from_le_bytes(tfd[4..12].try_into().unwrap()),
                ring.memory.first(3)
            );
            assert_eq!(u16::from_le_bytes([tfd[2], tfd[3]]), 20);
        }
    }

    #[test]
    fn a_response_returns_each_finished_frame_and_refuses_what_never_left() {
        let (mut ring, source, _domain, bytes) = ring(Family::Ax200, 16, 254);
        let fw = Firmware::parse(&bytes).unwrap();
        for _ in 0..4 {
            // SAFETY: the model queue is live.
            unsafe { ring.publish(&frame(&fw, Family::Ax200, 60), &source) }.unwrap();
        }
        assert_eq!(ring.write, 2);
        // SAFETY: the model finished these.
        let refused = unsafe { ring.reclaim(3) };
        assert_eq!(
            refused,
            Err(Error::Reclaim {
                read: 254,
                write: 2,
                next: 3
            })
        );
        // SAFETY: as above.
        assert_eq!(unsafe { ring.reclaim(0) }, Ok(2));
        assert_eq!(ring.used(), 2);
        assert_eq!(ring.pool.len(), 2);
        assert_eq!(&ring.memory.descriptor(14)[..2], &[1, 0]);
        // SAFETY: as above.
        assert_eq!(unsafe { ring.reclaim(2) }, Ok(2));
        // SAFETY: as above.
        assert_eq!(unsafe { ring.reclaim(2) }, Ok(0));
        let before = source.calls.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: the pool's buffers serve the next frames.
        unsafe { ring.publish(&frame(&fw, Family::Ax200, 60), &source) }.unwrap();
        assert_eq!(
            source.calls.load(core::sync::atomic::Ordering::Relaxed),
            before
        );
    }

    #[test]
    fn a_full_queue_waits_and_a_long_frame_is_refused() {
        let (mut ring, source, _domain, bytes) = ring(Family::Ax210, 16, 0);
        let fw = Firmware::parse(&bytes).unwrap();
        for _ in 0..16 {
            // SAFETY: the model queue is live.
            unsafe { ring.publish(&frame(&fw, Family::Ax210, 60), &source) }.unwrap();
        }
        // SAFETY: as above.
        let full = unsafe { ring.publish(&frame(&fw, Family::Ax210, 60), &source) };
        assert!(matches!(full, Err(Error::Full)));
        // SAFETY: as above.
        unsafe { ring.reclaim(16) }.unwrap();
        // SAFETY: as above.
        let long = unsafe { ring.publish(&frame(&fw, Family::Ax210, 4096), &source) };
        assert!(matches!(long, Err(Error::FrameLength)));
        assert_eq!(ring.used(), 0);
    }

    #[test]
    fn a_data_queue_holds_the_full_pointer_range_less_one_on_ax200() {
        let (mut ring, source, _domain, bytes) = ring(Family::Ax200, 256, 0);
        let fw = Firmware::parse(&bytes).unwrap();
        assert_eq!(ring.space(), 255);
        for _ in 0..255 {
            // SAFETY: the model queue is live.
            unsafe { ring.publish(&frame(&fw, Family::Ax200, 60), &source) }.unwrap();
        }
        assert_eq!(ring.space(), 0);
        assert!(ring.uncertain());
    }
}
