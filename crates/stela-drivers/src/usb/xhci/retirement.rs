// SPDX-License-Identifier: GPL-2.0-only
//! Whole-slot retirement before Disable Slot (xHCI 4.6.4).
//!
//! Linux xhci_free_dev receives a device whose traffic was already stopped by
//! usb_disconnect. Native enumeration failures must establish that same fact;
//! an unpublished descriptor inventory does not mean EP0 stopped running.
use super::*;
use reset::Ownership;

type Failure = (&'static str, BlockError);
const ENDPOINT_DISABLED: u32 = 0;

/// Minted only after the actual whole-slot retirement boundary. Its fields are
/// private to this module, so a software status or slot number cannot return DMA.
pub(super) struct Unpublished {
    slot: u8,
    state: Slot,
}

impl Unpublished {
    pub(super) fn into_slot(self) -> (u8, Slot) {
        (self.slot, self.state)
    }
}

/// The mutable controller borrow is retained from the last acknowledged
/// endpoint retirement through Disable Slot. No caller can publish another TD,
/// run private recovery control, or substitute a different device generation
/// between those operations. This authority is private and cannot be copied.
struct Quiesced<'a> {
    controller: &'a mut Controller,
    slot: u8,
    ownership: Ownership,
}

impl Controller {
    /// Fence the complete generation, retire every actual endpoint and receive
    /// its ordered events, then acknowledge Disable Slot before clearing DCBAA.
    /// A failure retains the original slot, contexts, rings and physical-current
    /// grant. Only a never-published device can return to `Vacant`; published
    /// generations keep all allocations and permanently refuse old aliases.
    /// Only unpublished EP0-only resources enter the private retry cache.
    pub(super) fn disable_slot(&mut self, slot: u8, ownership: Ownership) -> Result<(), Failure> {
        Quiesced::acquire(self, slot, ownership)?.disable()
    }
}

impl<'a> Quiesced<'a> {
    fn acquire(
        controller: &'a mut Controller,
        slot: u8,
        ownership: Ownership,
    ) -> Result<Self, Failure> {
        let index = usize::from(slot);
        if slot == 0
            || index >= controller.slots.len()
            || controller.slot_ownership.get(index) != Some(&Ownership::Enabled)
            || !matches!(ownership, Ownership::Vacant | Ownership::Retired)
        {
            return Err((
                "preflight Disable Slot ownership",
                BlockError::Unsupported("invalid xHCI slot retirement owner"),
            ));
        }
        let state = controller.slots.get_mut(index).and_then(Option::as_mut);
        let unaddressed = if let Some(state) = state {
            if ownership == Ownership::Vacant
                && (state.inventory.is_some()
                    || state.consumer != identity::Consumer::Unclaimed
                    || state
                        .endpoints
                        .iter()
                        .enumerate()
                        .any(|(dci, endpoint)| dci != 1 && endpoint.is_some())
                    || state.retired_rings.iter().any(Option::is_some)
                    || state.endpoints[1]
                        .as_ref()
                        .is_none_or(|ep0| ep0.streams.is_some() || ep0.iso.is_some()))
            {
                return Err((
                    "preflight unpublished Disable Slot",
                    BlockError::Unsupported("published xHCI slot cannot become vacant"),
                ));
            }
            // Address Device has not succeeded and no EP0 doorbell could have
            // been published while this initial generation fence was held.
            // Such a failed command may leave the zeroed EP0 context Disabled;
            // Stop/Set Dequeue would be illegal in that hardware state.
            let unaddressed = ownership == Ownership::Vacant
                && state.retiring
                && state.inventory.is_none()
                && state.consumer == identity::Consumer::Unclaimed
                && state.current_configuration == Some(0)
                && state.endpoints.iter().skip(2).all(Option::is_none)
                && state.endpoints[1].as_ref().is_some_and(|endpoint| {
                    endpoint.ring.index == 0
                        && endpoint.ring.cycle
                        && endpoint.in_flight == 0
                        && endpoint.streams.is_none()
                        && endpoint.iso.is_none()
                });
            state.retiring = true;
            unaddressed
        } else {
            // The Enable Slot grant may need returning when reservation failed
            // before any contexts were published. Never infer this from absence
            // of a software record if DCBAA still names a DMA allocation.
            if ownership != Ownership::Vacant || controller.dcbaa.read::<u64>(index * 8) != 0 {
                return Err((
                    "preflight unaddressed Disable Slot",
                    BlockError::Unsupported("xHCI slot allocation ownership unresolved"),
                ));
            }
            true
        };
        controller
            .ready()
            .map_err(|error| ("pre-Disable Slot controller status", error))?;
        let context = controller.context();
        let mut failure = None;
        for dci in 1..32usize {
            let Some(state) = controller.slots[index].as_ref() else {
                break;
            };
            if state.endpoints[dci].is_none() {
                continue;
            }
            fence(Ordering::Acquire);
            let endpoint_state = state._output.read::<u32>(dci * context) & 7;
            if unaddressed && dci == 1 && endpoint_state == ENDPOINT_DISABLED {
                continue;
            }
            // The complete software endpoint set is visited even after one
            // contributor fails. No Disable Slot is published on partial success.
            if let Err(error) = controller.cancel_inner(slot, dci as u8) {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(("retire every endpoint before Disable Slot", error));
        }
        controller
            .ready()
            .map_err(|error| ("pre-Disable Slot event retirement", error))?;
        // Recheck actual device contexts after every cancellation and its event
        // drain, rather than accepting a software queue count as an idle proof.
        if let Some(state) = controller.slots[index].as_ref() {
            fence(Ordering::Acquire);
            for (dci, endpoint) in state.endpoints.iter().enumerate().skip(1) {
                if let Some(endpoint) = endpoint {
                    let actual = state._output.read::<u32>(dci * context) & 7;
                    if endpoint.poisoned
                        || ownership == Ownership::Vacant
                            && (endpoint.in_flight != 0 || !endpoint.ring.normal.idle())
                        || !(actual == ENDPOINT_STOPPED
                            || unaddressed && dci == 1 && actual == ENDPOINT_DISABLED)
                    {
                        return Err((
                            "verify stopped endpoint before Disable Slot",
                            BlockError::Unsupported("xHCI slot endpoint retirement unresolved"),
                        ));
                    }
                }
            }
        }
        Ok(Self {
            controller,
            slot,
            ownership,
        })
    }

    fn disable(self) -> Result<(), Failure> {
        let Self {
            controller,
            slot,
            ownership,
        } = self;
        let completion = controller
            .command(0, 0, reset::DISABLE_SLOT << 10 | u32::from(slot) << 24)
            .map_err(|error| ("acknowledge Disable Slot", error))?;
        if completion.slot() != slot {
            controller.command_poisoned = true;
            return Err((
                "acknowledge Disable Slot identity",
                BlockError::Unsupported("Disable Slot completion named another slot"),
            ));
        }
        // The acknowledged Disable can already have ended the first address
        // lifetime even if the following controller health check fails. Never
        // permit a retained raw slot number to regain authority.
        controller.legacy_slot_fenced[usize::from(slot)] = true;
        controller
            .ready()
            .map_err(|error| ("post-Disable Slot controller status", error))?;
        controller
            .pending
            .retain(|event| !(event.kind() == TRANSFER_EVENT && event.slot() == slot));
        controller.slot_ownership[usize::from(slot)] = ownership;
        controller.dcbaa.write(usize::from(slot) * 8, 0u64);
        if ownership == Ownership::Vacant
            && let Some(state) = controller.slots[usize::from(slot)].take()
        {
            controller
                .retry_resources
                .retain(Unpublished { slot, state });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
