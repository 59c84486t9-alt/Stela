// SPDX-License-Identifier: GPL-2.0-only
//! Clear real USB2 transaction-translator buffers after acknowledged child
//! endpoint retirement, following hub.c hub_clear_tt_buffer/usb_hub_clear_tt_buffer.
use super::*;

const CLEAR_TT_BUFFER: u8 = 8;
const SLOT_MULTI_TT: u32 = 1 << 25;
const DEVICE_ADDRESS_MASK: u32 = 0x7f;
const ENDPOINT_TYPE_SHIFT: u32 = 3;
const ENDPOINT_TYPE_MASK: u32 = 7;
const CONTROL_TYPE: u32 = 4;
const BULK_OUT_TYPE: u32 = 2;
const BULK_IN_TYPE: u32 = 6;
const DEVINFO_BULK: u16 = 2 << 11;
const DEVINFO_IN: u16 = 1 << 15;

impl Controller {
    /// The transfer owner selects actual split errors, excluding EP0 protocol
    /// STALL, then calls this after Stop/Reset/Set Dequeue and before unpoison.
    /// A failed clear preserves that owner's poison and retained DMA.
    pub(in super::super) fn clear_hub_tt(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.ready()?;
        if self.slot_ownership.get(usize::from(slot)) != Some(&reset::Ownership::Enabled) {
            return Err(BlockError::Unsupported(
                "USB2 TT clear child slot is not hardware-enabled",
            ));
        }
        // Private cancellation may already have quarantined this child. No
        // child transfer is published here, so its retiring bit is allowed;
        // the TT hub itself must still be live for its actual EP0 request.
        let attachment = self.slot(slot)?.attachment;
        let Some((hub, port)) = attachment.translator else {
            return Ok(());
        };
        if !matches!(attachment.speed, LOW_SPEED | FULL_SPEED) || !(1..32).contains(&dci) {
            return Err(BlockError::Unsupported("invalid USB2 split endpoint owner"));
        }
        let context = self.context();
        fence(Ordering::Acquire);
        let state = self.slot(slot)?;
        let endpoint =
            state.endpoints[usize::from(dci)]
                .as_ref()
                .ok_or(BlockError::Unsupported(
                    "USB2 split endpoint is not configured",
                ))?;
        if !endpoint.enabled {
            return Err(BlockError::Unsupported(
                "USB2 split endpoint has no Configure ACK",
            ));
        }
        let word0 = state._output.read::<u32>(usize::from(dci) * context);
        let word1 = state._output.read::<u32>(usize::from(dci) * context + 4);
        let kind = word1 >> ENDPOINT_TYPE_SHIFT & ENDPOINT_TYPE_MASK;
        // TT buffer recovery is for control/bulk, never interrupt/isochronous.
        if matches!(kind, 1 | 3 | 5 | 7) {
            return Ok(());
        }
        if !matches!(kind, CONTROL_TYPE | BULK_OUT_TYPE | BULK_IN_TYPE)
            || (kind == CONTROL_TYPE) != (dci == 1)
            || kind == BULK_OUT_TYPE && dci & 1 != 0
            || kind == BULK_IN_TYPE && dci & 1 == 0
        {
            return Err(BlockError::Unsupported(
                "USB2 split endpoint context type mismatch",
            ));
        }
        if word0 & 7 != ENDPOINT_STOPPED {
            return Err(BlockError::Unsupported(
                "USB2 TT clear requires acknowledged endpoint stop",
            ));
        }
        let address = state._output.read::<u32>(12) & DEVICE_ADDRESS_MASK;
        if address == 0 {
            return Err(BlockError::Unsupported(
                "USB2 TT clear requires actual addressed slot context",
            ));
        }
        self.live_slot(hub)?;
        let parent = self.slot(hub)?;
        if parent.attachment.speed != HIGH_SPEED {
            return Err(BlockError::Unsupported(
                "USB2 transaction translator is not a high-speed hub",
            ));
        }
        let multi = parent.context[0] & SLOT_MULTI_TT != 0;
        let ports = self.power.hub_ports(hub).ok_or(BlockError::Unsupported(
            "USB2 transaction translator hub contract absent",
        ))?;
        if port == 0
            || port > ports
            || self.power.powered_ports(hub)? & (1 << port) == 0
            || !self.power.belongs_to(slot, hub)
        {
            return Err(BlockError::Unsupported(
                "USB2 transaction translator port authority absent",
            ));
        }
        self.observe_current_ancestors(slot, false)?;
        let tt = if multi { u16::from(port) } else { 1 };
        let devinfo = u16::from(dci / 2)
            | (address as u16) << 4
            | if kind == CONTROL_TYPE {
                0
            } else {
                DEVINFO_BULK
            }
            | if dci & 1 != 0 { DEVINFO_IN } else { 0 };
        if kind == CONTROL_TYPE {
            // Donor clears the opposite direction first, then the requested one.
            self.control(
                hub,
                setup(0x23, CLEAR_TT_BUFFER, devinfo ^ DEVINFO_IN, tt, 0),
                &[],
            )?;
        }
        self.control(hub, setup(0x23, CLEAR_TT_BUFFER, devinfo, tt, 0), &[])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{model::*, tests::controller},
        *,
    };
    use crate::bus::dma::RegionAllocator;
    use alloc::collections::BTreeMap;

    #[test]
    fn tt_clear_uses_actual_device_address_endpoint_direction_and_committed_multi_tt_port() {
        for multi in [false, true] {
            for context in [32, 64] {
                let mut hub = Node::hub(HIGH_SPEED, 3);
                hub.multi_tt = multi;
                for port in &mut hub.ports.as_mut().unwrap()[..2] {
                    port.status = 0;
                    port.change = 0;
                }
                hub.ports.as_mut().unwrap()[2].child_speed = FULL_SPEED;
                let nodes = BTreeMap::from([(0, hub), (3, Node::leaf(FULL_SPEED))]);
                let mut backing = vec![0u64; 256 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: actual child/TT context and EP0 TRBs retain this RAM.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut c, model) = controller(&mut dma, context, nodes);
                let mut failures = Vec::new();
                let devices = c.enumerate(&mut dma, &mut failures);
                assert!(failures.is_empty(), "{failures:?}");
                let child = devices
                    .iter()
                    .find(|d| d.descriptor[4] != HUB_CLASS)
                    .unwrap();
                let endpoints = interfaces(&child.configuration)[0].endpoints.clone();
                c.set_configuration(child.slot, child.configuration_value())
                    .unwrap();
                c.configure(child.slot, &endpoints, None, &mut dma).unwrap();
                assert_eq!(
                    c.slot(child.slot).unwrap().attachment.translator,
                    Some((1, 3))
                );
                let before = model.borrow().requests.len();
                assert!(c.clear_hub_tt(child.slot, 1).is_err());
                assert_eq!(model.borrow().requests.len(), before);
                let address =
                    c.slot(child.slot).unwrap()._output.read::<u32>(12) & DEVICE_ADDRESS_MASK;
                assert_ne!(address, u32::from(child.slot));
                let tt = if multi { 3 } else { 1 };
                for dci in [1u8, 3, 4] {
                    c.cancel(child.slot, dci).unwrap();
                    c.clear_hub_tt(child.slot, dci).unwrap();
                }
                let hardware = model.borrow();
                let requests: Vec<_> = hardware
                    .requests
                    .iter()
                    .filter(|(_, _, q)| q[0] == 0x23 && q[1] == CLEAR_TT_BUFFER)
                    .map(|(_, _, q)| *q)
                    .collect();
                let address = (address as u16) << 4;
                assert_eq!(
                    requests,
                    [
                        setup(0x23, CLEAR_TT_BUFFER, address, tt, 0),
                        setup(0x23, CLEAR_TT_BUFFER, address | DEVINFO_IN, tt, 0),
                        setup(
                            0x23,
                            CLEAR_TT_BUFFER,
                            1 | address | DEVINFO_BULK | DEVINFO_IN,
                            tt,
                            0
                        ),
                        setup(0x23, CLEAR_TT_BUFFER, 2 | address | DEVINFO_BULK, tt, 0),
                    ]
                );
            }
        }
    }

    #[test]
    fn tt_clear_refuses_missing_address_and_propagates_actual_hub_control_failure() {
        let mut hub = Node::hub(HIGH_SPEED, 1);
        hub.ports.as_mut().unwrap()[0].child_speed = FULL_SPEED;
        let nodes = BTreeMap::from([(0, hub), (1, Node::leaf(FULL_SPEED))]);
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: fault injection retains the actual child/parent DMA allocations.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut c, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        c.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty());
        c.cancel(2, 1).unwrap();
        let word = c.slot(2).unwrap()._output.read::<u32>(12);
        c.slot(2)
            .unwrap()
            ._output
            .write(12, word & !DEVICE_ADDRESS_MASK);
        let before = model.borrow().requests.len();
        assert!(c.clear_hub_tt(2, 1).is_err());
        assert_eq!(model.borrow().requests.len(), before);
        c.slot(2).unwrap()._output.write(12, word);
        let address = ((word & DEVICE_ADDRESS_MASK) as u16) << 4;
        let opposite = setup(0x23, CLEAR_TT_BUFFER, address, 1, 0);
        let requested = setup(0x23, CLEAR_TT_BUFFER, address | DEVINFO_IN, 1, 0);
        c.slot(2).unwrap().endpoints[1].as_mut().unwrap().poisoned = true;
        model.borrow_mut().effect_fail = Some((1, opposite));
        assert!(c.clear_hub_tt(2, 1).is_err());
        assert!(c.slot(2).unwrap().endpoints[1].as_ref().unwrap().poisoned);
        assert!(
            !model.borrow().requests[before..]
                .iter()
                .any(|(_, _, q)| *q == requested)
        );
        assert!(c.power.retained(2));
    }
}
