// SPDX-License-Identifier: GPL-2.0-only
//! Shared hostile raw consumers: no test grants production reuse authority.
use super::*;

pub(in crate::usb::xhci) fn refuse(controller: &mut Controller, slot: u8, buffer: u64, trb: u64) {
    struct NoAllocation;
    impl DmaAllocator for NoAllocation {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
            panic!("retired raw slot reached DMA allocation")
        }
    }
    let dma: &mut dyn DmaAllocator = &mut NoAllocation;
    struct NoAccess;
    impl Registers for NoAccess {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("retired raw slot reached MMIO read")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("retired raw slot reached MMIO write")
        }
    }
    let pending = |c: &Controller| {
        c.pending
            .iter()
            .map(|e| (e.parameter, e.status, e.control))
            .collect::<Vec<_>>()
    };
    let endpoint_state = |c: &Controller| {
        c.slots
            .iter()
            .flatten()
            .flat_map(|s| {
                s.endpoints.iter().flatten().map(|e| {
                    (
                        e.ring.index,
                        e.ring.cycle,
                        e.in_flight,
                        e.enabled,
                        e.poisoned,
                    )
                })
            })
            .collect::<Vec<_>>()
    };
    let before_pending = pending(controller);
    let before_endpoints = endpoint_state(controller);
    let before_cursor = (
        controller.event_index,
        controller.event_cycle,
        controller.commands.index,
        controller.commands.cycle,
    );
    let before_slots = controller
        .slots
        .iter()
        .map(|s| {
            s.as_ref()
                .map(|s| (s.generation, s.retiring, s.current_configuration))
        })
        .collect::<Vec<_>>();
    let registers = core::mem::replace(&mut controller.registers, Box::new(NoAccess));
    let hostile = Endpoint {
        address: 0xff,
        attributes: 1,
        max_packet: 0,
        interval: 0,
        companion: None,
    };
    macro_rules! refused {
        ($result:expr) => {
            assert!(matches!(
                $result,
                Err(BlockError::Unsupported(
                    "raw xHCI slot authority is permanently retired"
                ))
            ));
        };
    }
    refused!(controller.current_configuration(slot));
    refused!(controller.set_configuration(slot, 0));
    refused!(controller.control(slot, setup(0, SET_CONFIGURATION, 0, 0, 0), &[]));
    assert_eq!(controller.string(slot, LANGUAGE_EN_US, 1), None);
    assert_eq!(controller.string(slot, LANGUAGE_EN_US, 0), None);
    refused!(controller.connected(slot));
    refused!(controller.configure(slot, core::slice::from_ref(&hostile), None, dma));
    refused!(controller.preflight_endpoints(slot, core::slice::from_ref(&hostile)));
    refused!(controller.deconfigure(slot, core::slice::from_ref(&hostile)));
    refused!(controller.configure_streams(slot, core::slice::from_ref(&hostile), &[0xff], 2, dma));
    refused!(controller.stream_capacity(slot, core::slice::from_ref(&hostile), &[0xff], 2));
    refused!(controller.reset_endpoint(slot, &hostile));
    refused!(controller.clear(slot, &hostile));
    for dci in [3, 255] {
        refused!(controller.endpoint_ready(slot, dci));
        refused!(controller.submit(slot, dci, buffer, 64));
        refused!(controller.submit_ticket(slot, dci, buffer, 64));
        assert!(matches!(
            controller.completed(slot, dci, trb, 64),
            Some(Err(BlockError::Unsupported(
                "raw xHCI slot authority is permanently retired"
            )))
        ));
        refused!(controller.transfer(slot, dci, buffer, 64, 1));
        refused!(controller.submit_stream(slot, dci, 1, buffer, 64));
        refused!(controller.submit_iso(slot, dci, buffer, 64));
        refused!(controller.submit_iso_scheduled(slot, dci, buffer, 64, IsoSchedule::Asap));
        refused!(controller.iso_schedule_list(slot, dci, IsoSchedule::Asap, 1));
        refused!(controller.cancel(slot, dci));
    }
    controller.quarantine_slot(slot);
    assert_eq!(pending(controller), before_pending);
    assert_eq!(endpoint_state(controller), before_endpoints);
    assert_eq!(
        (
            controller.event_index,
            controller.event_cycle,
            controller.commands.index,
            controller.commands.cycle
        ),
        before_cursor
    );
    assert_eq!(
        controller
            .slots
            .iter()
            .map(|s| s
                .as_ref()
                .map(|s| (s.generation, s.retiring, s.current_configuration)))
            .collect::<Vec<_>>(),
        before_slots
    );
    controller.registers = registers;
}
