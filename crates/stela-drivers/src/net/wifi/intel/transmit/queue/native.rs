// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Private queue memory for the unique acknowledged native station owner.
use super::*;

pub(in crate::net::wifi::intel) struct NativeMemory {
    memory: UnpublishedQueue,
    released: bool,
    exposed: bool,
}
impl NativeMemory {
    pub(in crate::net::wifi::intel) fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        Ok(Self {
            memory: UnpublishedQueue::prepare(fw, family, source, domain)?,
            released: false,
            exposed: false,
        })
    }
    pub(in crate::net::wifi::intel) fn configuration(
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
    pub(in crate::net::wifi::intel) fn layout(&self) -> Layout {
        self.memory.layout()
    }
    pub(in crate::net::wifi::intel) fn slots(&self) -> u16 {
        self.memory.slots()
    }
    /// # Safety
    /// The requester/coherent domain is the native epoch's.
    /// All required real policy leases are held through this handoff and its
    /// following HCMD. The CPU has exclusive ownership of this fresh memory;
    /// no queue/frame or address has previously been submitted from it.
    pub(in crate::net::wifi::intel) unsafe fn expose(&mut self) -> Result<(), Error> {
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
    pub(in crate::net::wifi::intel) fn released(&self) -> bool {
        self.released
    }
    pub(in crate::net::wifi::intel) fn uncertain(&self) -> bool {
        self.exposed && !self.released
    }
    /// # Safety
    /// Scheduler REMOVE ACK/reclaim or independent native stop has
    /// ended all device access; no frame or queue worker can reference these
    /// mappings. Every pending descriptor has completed and reclaimed. A failed
    /// invalidation must keep the same native/policy owner with this memory.
    pub(in crate::net::wifi::intel) unsafe fn release(&mut self) -> Result<(), Error> {
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
