//! Exclusive root-device reset and fresh identification, with no slot-ID reuse.
// SPDX-License-Identifier: GPL-2.0-only
// Linux a804c574 usb/core/hub.c and usb/host/xhci.c/xhci-hub.c;
// Intel xHCI1.2b4.5.3.3,4.6.4,4.19.5,5.4.8. See THIRD_PARTY.md.
use super::*;

pub(super) const DISABLE_SLOT: u32 = 10;
const PORT_STATUS_CHANGE: u32 = 34;
const POST_RESET_US: u64 = 50_000;
pub(super) const EXHAUSTED: &str = "xHCI boot-lifetime non-recycled slot budget exhausted";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ownership {
    Vacant,
    Enabled,
    /// Disable Slot completed; a later Enable Slot may hand this ID back.
    Retired,
    /// That Enable Slot was acknowledged and deliberately remains unaddressed.
    Tombstone,
}
impl Controller {
    /// Pure guard before any stale bare-slot API can touch MMIO or DMA.
    pub(super) fn live_slot(&self, slot: u8) -> Result<(), BlockError> {
        let index = usize::from(slot);
        if self.slot_ownership.get(index) != Some(&Ownership::Enabled)
            || self
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .is_none_or(|slot| slot.retiring)
        {
            return Err(BlockError::Unsupported(
                "xHCI slot is absent or permanently retired",
            ));
        }
        Ok(())
    }
    /// Permanently block class reconstruction failure; this is not a claim
    /// that hardware/DMA has stopped. All original allocations remain retained.
    pub(crate) fn quarantine_slot(&mut self, slot: u8) {
        if let Some(Some(slot)) = self.slots.get_mut(usize::from(slot)) {
            slot.retiring = true;
        }
    }

    pub(super) fn fresh_slot(&mut self) -> Result<u8, BlockError> {
        if self
            .slot_ownership
            .iter()
            .skip(1)
            .all(|state| *state != Ownership::Vacant)
        {
            return Err(BlockError::Unsupported(EXHAUSTED));
        }
        for _ in 0..self.max_slots {
            let event = self.command(0, 0, ENABLE_SLOT << 10)?;
            let id = usize::from(event.slot());
            if id == 0 || id > self.max_slots || id >= self.slot_ownership.len() {
                self.command_poisoned = true;
                return Err(BlockError::Unsupported("xHCI slot ID out of range"));
            }
            match self.slot_ownership[id] {
                Ownership::Vacant => {
                    // Keep this grant even if any following allocation fails.
                    // Enabled slots do not fetch DCBAA or accept doorbells.
                    self.slot_ownership[id] = Ownership::Enabled;
                    return Ok(id as u8);
                }
                Ownership::Retired => self.slot_ownership[id] = Ownership::Tombstone,
                Ownership::Enabled | Ownership::Tombstone => {
                    self.command_poisoned = true;
                    return Err(BlockError::Unsupported(
                        "xHCI returned an already-owned slot ID",
                    ));
                }
            }
        }
        Err(BlockError::Unsupported(EXHAUSTED))
    }

    /// # Safety
    /// The caller exclusively owns this complete device and has permanently
    /// invalidated all class aliases. Endpoints must be the complete current
    /// configured DCI set. This bounded service supports root attachments only;
    /// it does not authorize resetting a hub or another interface's device.
    pub(crate) unsafe fn reset_and_identify(
        &mut self,
        device: &Device,
        endpoints: &[Endpoint],
        dma: &mut dyn DmaAllocator,
    ) -> Result<Device, (String, BlockError)> {
        during(
            "reset exclusive root device preflight",
            self.reset_preflight(device, endpoints),
        )?;
        let slot = device.slot;
        let attachment = self.slot(slot).unwrap().attachment;
        self.slot(slot).unwrap().retiring = true;
        let mut failed = None;
        for dci in 1..32 {
            if self.slot(slot).unwrap().endpoints[dci].is_some()
                && let Err(error) = self.cancel_inner(slot, dci as u8)
            {
                failed.get_or_insert(error);
            }
        }
        if let Some(error) = failed {
            return Err(("retire every endpoint before Disable Slot".into(), error));
        }
        // 4.6.4 requires all active endpoints stopped/idle and all transfer and
        // command events received BEFORE Disable Slot. cancel_inner supplies
        // acknowledged Stop/Reset/SetDequeue and drains every stream's events.
        self.disable_slot(slot, Ownership::Retired)
            .map_err(|(operation, error)| (operation.into(), error))?;
        during(
            "acknowledge physical root-port reset",
            self.reset_root_device(attachment),
        )?;
        let result = self.identify(attachment, device.location.clone(), dma);
        if result.is_err() {
            // A failed fresh enumeration may already have acknowledged Address
            // Device and EP0. Keep that new grant inaccessible as well.
            for slot in self.slots.iter_mut().flatten() {
                if slot.attachment.root_port == attachment.root_port
                    && slot.attachment.route == attachment.route
                {
                    slot.retiring = true;
                }
            }
        }
        result
    }
    /// Disable Slot (xHCI 4.6.4) and clear the slot's DCBAA entry, leaving
    /// it `ownership`: `Vacant` for a slot no driver was ever given, which
    /// Linux `xhci_free_dev` disables the same way, or `Retired` after a
    /// reset, since stale class handles may still name it. Old contexts and
    /// rings stay allocated in the slot record until the ID is reused.
    pub(super) fn disable_slot(
        &mut self,
        slot: u8,
        ownership: Ownership,
    ) -> Result<(), (&'static str, BlockError)> {
        let fail = |operation| move |error| (operation, error);
        self.ready()
            .map_err(fail("pre-Disable Slot event retirement"))?;
        let completion = self
            .command(0, 0, DISABLE_SLOT << 10 | u32::from(slot) << 24)
            .map_err(fail("acknowledge Disable Slot"))?;
        if completion.slot() != slot {
            self.command_poisoned = true;
            return Err((
                "acknowledge Disable Slot identity",
                BlockError::Unsupported("Disable Slot completion named another slot"),
            ));
        }
        self.drain();
        self.ready()
            .map_err(fail("post-Disable Slot controller status"))?;
        self.pending
            .retain(|event| !(event.kind() == TRANSFER_EVENT && event.slot() == slot));
        self.slot_ownership[usize::from(slot)] = ownership;
        self.dcbaa.write(usize::from(slot) * 8, 0u64);
        if ownership == Ownership::Vacant {
            self.slots[usize::from(slot)] = None;
        }
        Ok(())
    }

    fn reset_preflight(&self, device: &Device, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        self.live_slot(device.slot)?;
        let slot = self.slots[usize::from(device.slot)].as_ref().unwrap();
        let a = slot.attachment;
        if a.tier != 0
            || a.route != 0
            || a.translator.is_some()
            || a.root_port == 0
            || a.root_port > self.max_ports
            || a.speed != device.speed
        {
            return Err(BlockError::Unsupported(
                "USB reset currently requires the original root attachment",
            ));
        }
        if self.slots.iter().enumerate().any(|(id, candidate)| {
            id != usize::from(device.slot)
                && self.slot_ownership[id] == Ownership::Enabled
                // A grant without completed attachment metadata is unknown;
                // do not infer that resetting this port cannot affect it.
                && candidate
                    .as_ref()
                    .is_none_or(|other| other.attachment.root_port == a.root_port)
        }) {
            return Err(BlockError::Unsupported(
                "USB reset root port has another unretired slot owner",
            ));
        }
        if slot.current_configuration != Some(device.configuration_value())
            || device.configuration_value() == 0
        {
            return Err(BlockError::Unsupported(
                "USB reset configuration does not match attachment",
            ));
        }
        let mut expected = 0u32;
        for endpoint in endpoints {
            let dci = endpoint.dci();
            if dci < 2 || expected & (1 << dci) != 0 {
                return Err(BlockError::Unsupported(
                    "USB reset exclusive endpoint inventory",
                ));
            }
            expected |= 1 << dci;
        }
        let actual = slot
            .endpoints
            .iter()
            .enumerate()
            .skip(2)
            .fold(0u32, |bits, (dci, endpoint)| {
                bits | if endpoint.is_some() { 1 << dci } else { 0 }
            });
        if expected == 0 || expected != actual {
            return Err(BlockError::Unsupported(
                "USB reset does not exclusively own every configured endpoint",
            ));
        }
        Ok(())
    }
    fn reset_root_device(&mut self, attachment: Attachment) -> Result<(), BlockError> {
        let port = attachment.root_port;
        let at = self.port_offset(port);
        let before = self.registers.read32(at);
        if before & (CCS | PP) != CCS | PP {
            return Err(BlockError::Unsupported(
                "USB reset root device is disconnected or unpowered",
            ));
        }
        // Clear all prior change bits to establish a fresh PRC/event transition.
        self.write_port(port, before & PORT_CHANGES);
        self.drain();
        if self.registers.read32(at) & PORT_CHANGES != 0 {
            return Err(BlockError::Unsupported(
                "USB reset could not acknowledge previous port changes",
            ));
        }
        self.write_port(port, PR);
        let deadline = self.clock.deadline(PORT_RESET_US);
        let mut acknowledged_event = false;
        loop {
            let status = self.registers.read32(self.operational + USBSTS);
            if status & (HSE | HCE) != 0 {
                self.error = Some(status);
                self.command_poisoned = true;
                return Err(BlockError::Device { status });
            }
            while let Some(event) = self.next_event() {
                if event.kind() == PORT_STATUS_CHANGE && event.parameter == u64::from(port) << 24 {
                    if event.code() != SUCCESS {
                        return Err(BlockError::Device {
                            status: event.code(),
                        });
                    }
                    acknowledged_event = true;
                } else if matches!(event.kind(), TRANSFER_EVENT | COMMAND_COMPLETION) {
                    self.pending.push(event);
                }
            }
            let portsc = self.registers.read32(at);
            if acknowledged_event && portsc & PRC != 0 && portsc & PR == 0 {
                if portsc & (CCS | PED) != CCS | PED
                    || (portsc >> 10 & 15) as u8 != attachment.speed
                    || matches!(attachment.speed, SUPER_SPEED | SUPER_SPEED_PLUS)
                        && portsc & PLS != 0
                {
                    return Err(BlockError::Unsupported(
                        "USB root reset did not restore the original enabled link",
                    ));
                }
                self.write_port(port, portsc & PORT_CHANGES);
                self.clock.delay(POST_RESET_US);
                return Ok(());
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
