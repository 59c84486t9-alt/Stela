// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Private queue memory for the unique acknowledged native station owner.
use super::*;
#[cfg(test)]
use alloc::vec::Vec;

pub(in crate::wifi::intel) struct NativeMemory {
    memory: UnpublishedQueue,
    released: bool,
    exposed: bool,
}
impl NativeMemory {
    pub(in crate::wifi::intel) fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        slots: u16,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        Ok(Self {
            memory: UnpublishedQueue::prepare(fw, family, slots, source, domain)?,
            released: false,
            exposed: false,
        })
    }
    pub(in crate::wifi::intel) fn configuration(
        &self,
        station_mask: u32,
        tid: u8,
    ) -> Result<Configuration, Error> {
        let layout = self.layout();
        Configuration::encode(
            self.memory.family,
            Parameters {
                station_mask,
                tid,
                slots: self.slots(),
                byte_counts: layout.byte_counts,
                descriptors: layout.descriptors,
            },
        )
    }
    pub(in crate::wifi::intel) fn layout(&self) -> Layout {
        self.memory.layout()
    }
    pub(in crate::wifi::intel) fn slots(&self) -> u16 {
        self.memory.slots()
    }
    /// # Safety
    /// The requester/coherent domain is the native epoch's.
    /// All required real policy leases are held through this handoff and its
    /// following HCMD. The CPU has exclusive ownership of this fresh memory;
    /// no queue/frame or address has previously been submitted from it.
    pub(in crate::wifi::intel) unsafe fn expose(&mut self) -> Result<(), Error> {
        if self.released || self.exposed {
            return Err(Error::Region);
        }
        // An uncertain later handoff or HCMD cannot let Drop unmap any part of
        // this potentially device-reachable memory before real quiescence.
        self.memory.byte_counts.expose();
        self.memory.descriptors.expose();
        self.memory.first.expose();
        self.memory.invalid.expose();
        self.exposed = true;
        for chunk in [
            &self.memory.byte_counts,
            &self.memory.descriptors,
            &self.memory.first,
            &self.memory.invalid,
        ] {
            // SAFETY: fresh exclusive queue memory; visibility is completed
            // before the one native scheduler command publishes its addresses.
            unsafe { chunk.ready_for_device() }.map_err(Error::Dma)?;
        }
        Ok(())
    }
    /// TB0's address in `slot`.
    pub(in crate::wifi::intel) fn first(&self, slot: usize) -> u64 {
        self.memory.first.region().address + slot as u64 * 64
    }
    /// # Safety
    /// `slot`'s descriptor is invalid, so the device reads no TB0 there.
    pub(in crate::wifi::intel) unsafe fn write_first(
        &self,
        slot: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        // SAFETY: as the caller promises.
        unsafe { self.memory.first.write_owned(slot * 64, bytes) }.map_err(Error::Dma)
    }
    /// `iwl_pcie_gen2_update_byte_tbl` and the descriptor it describes.
    /// # Safety
    /// `slot` is past the published write pointer.
    pub(in crate::wifi::intel) unsafe fn write_descriptor(
        &self,
        slot: usize,
        tfd: &[u8],
        byte_count: u16,
    ) -> Result<(), Error> {
        // SAFETY: as the caller promises.
        unsafe {
            self.memory
                .byte_counts
                .write_owned(slot * 2, &byte_count.to_le_bytes())
                .map_err(Error::Dma)?;
            self.memory
                .descriptors
                .write_owned(slot * 256, tfd)
                .map_err(Error::Dma)
        }
    }
    /// `iwl_txq_set_tfd_invalid_gen2`: `slot` points at the invalid buffer.
    /// # Safety
    /// The device finished this slot's frame.
    pub(in crate::wifi::intel) unsafe fn invalidate(&self, slot: usize) -> Result<(), Error> {
        let tfd = Tfd::encode(&[self.memory.invalid.region()]).map_err(Error::Descriptor)?;
        // SAFETY: as the caller promises.
        unsafe { self.memory.descriptors.write_owned(slot * 256, tfd.bytes()) }.map_err(Error::Dma)
    }
    #[cfg(test)]
    pub(in crate::wifi::intel) fn byte_count(&self, slot: usize) -> u16 {
        let bytes =
            crate::wifi::intel::dma::tests::read_back(&self.memory.byte_counts, slot * 2, 2);
        u16::from_le_bytes([bytes[0], bytes[1]])
    }
    #[cfg(test)]
    pub(in crate::wifi::intel) fn descriptor(&self, slot: usize) -> Vec<u8> {
        crate::wifi::intel::dma::tests::read_back(&self.memory.descriptors, slot * 256, 256)
    }
    pub(in crate::wifi::intel) fn uncertain(&self) -> bool {
        self.exposed && !self.released
    }
    /// # Safety
    /// Scheduler REMOVE ACK/reclaim or independent native stop has
    /// ended all device access; no frame or queue worker can reference these
    /// mappings. Every pending descriptor has completed and reclaimed. A failed
    /// invalidation must keep the same native/policy owner with this memory.
    pub(in crate::wifi::intel) unsafe fn release(&mut self) -> Result<(), Error> {
        for chunk in [
            &mut self.memory.byte_counts,
            &mut self.memory.descriptors,
            &mut self.memory.first,
            &mut self.memory.invalid,
        ] {
            // SAFETY: source quiescence supplied by this method's owner.
            unsafe { chunk.release() }.map_err(|error| Error::Dma(dma::Error::Dma(error)))?;
        }
        self.released = true;
        Ok(())
    }
}
