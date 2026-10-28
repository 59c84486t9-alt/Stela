// SPDX-License-Identifier: GPL-2.0-only
// Endpoint retirement follows pinned Linux xhci.c/xhci-mem.c and xHCI 4.6.6.
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
//! Acknowledged endpoint removal before a class changes its alternate setting.
use super::*;

impl Controller {
    /// Quiesce and remove the exclusively owned endpoint DCIs before changing
    /// a USB interface. This does not issue SET_INTERFACE: the class owner must
    /// perform that actual request, then configure fresh endpoints. All selected
    /// DCIs are validated before any mutation. Every old TD requires successful
    /// Stop/Reset/Set Dequeue + drain, followed by Configure Endpoint Drop ACK.
    /// Any uncertain step retains and poisons every selected endpoint. Success
    /// permits DMA reuse. After the primary event ring has been drained and old
    /// endpoint events removed, retain the actual nonstream ring for this DCI.
    /// A replacement starts at its acknowledged producer pointer/cycle, without
    /// resetting the allocator, zeroing a live ring or replaying a ticket.
    /// Streams retain their separate allocation/retirement policy.
    pub fn deconfigure(
        &mut self,
        id: impl DeviceRef,
        endpoints: &[Endpoint],
    ) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        self.deconfigure_owned(slot, endpoints)
    }

    pub(super) fn deconfigure_owned(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
    ) -> Result<(), BlockError> {
        self.live_slot(slot)?;
        self.ready()?;
        if endpoints.is_empty() {
            return Err(BlockError::Unsupported("empty endpoint teardown"));
        }
        let mut selected = 0u32;
        for endpoint in endpoints {
            let dci = endpoint.dci();
            if endpoint.address & 0x70 != 0 || dci < 2 || selected & (1 << dci) != 0 {
                return Err(BlockError::Unsupported(
                    "invalid or duplicate teardown endpoint",
                ));
            }
            self.endpoint_ready_owned(slot, dci)?;
            selected |= 1 << dci;
        }
        let result = self.deconfigure_inner(slot, endpoints, selected);
        if result.is_err() {
            for endpoint in endpoints {
                if let Some(transfer) =
                    self.slot(slot)?.endpoints[usize::from(endpoint.dci())].as_mut()
                {
                    transfer.poisoned = true;
                }
            }
        }
        result
    }
    fn deconfigure_inner(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        selected: u32,
    ) -> Result<(), BlockError> {
        for endpoint in endpoints {
            self.cancel_inner(slot, endpoint.dci())?;
        }
        self.clear_input(slot)?;
        let context = self.context();
        let input = {
            let state = self.slot(slot)?;
            let last = (2..32usize)
                .rev()
                .find(|dci| selected & (1 << dci) == 0 && state.endpoints[*dci].is_some())
                .unwrap_or(1);
            let mut words = state.context;
            words[0] = words[0] & !(31 << 27) | (last as u32) << 27;
            state.input.write(0, selected);
            state.input.write(4, 1u32);
            for (n, word) in words.iter().enumerate() {
                state.input.write(context + 4 * n, *word);
            }
            (state.input.device_address(), words)
        };
        self.command(input.0, 0, CONFIGURE_ENDPOINT << 10 | u32::from(slot) << 24)?;
        self.ready()?;
        self.pending.retain(|event| {
            !(event.kind() == TRANSFER_EVENT
                && event.slot() == slot
                && selected & (1 << event.endpoint()) != 0)
        });
        let state = self.slot(slot)?;
        state.context = input.1;
        for endpoint in endpoints {
            let dci = usize::from(endpoint.dci());
            let transfer = state.endpoints[dci].take().unwrap();
            if transfer.streams.is_none() {
                // xHCI 1.2b 4.6.9 orders stopped-transfer events before Stop
                // completion; 4.6.10 retires cached TDs. After Drop completion
                // (4.6.6), the shared primary ring and selected pending events
                // have both been drained above. Linux xhci_check_bandwidth
                // likewise frees dropped rings only after this command result.
                // No class can enqueue on the removed endpoint in this epoch.
                state.retired_rings[dci] = Some(transfer.ring);
            }
        }
        Ok(())
    }
}
