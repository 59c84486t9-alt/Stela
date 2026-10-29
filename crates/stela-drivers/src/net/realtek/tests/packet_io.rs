// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Packet io cases.
use super::*;

/// An RTL8169S over `registers` and `memory`, its rings in `memory`.
fn modelled(registers: &mut [u32], memory: &mut [u64], signalled: bool) -> Realtek {
    use crate::bus::dma::RegionAllocator;
    let start = memory.as_mut_ptr() as u64;
    // SAFETY: the caller owns both allocations for the driver's lifetime.
    let (device, mut dma) = unsafe {
        (
            Mmio::new(registers.as_mut_ptr() as u64),
            RegionAllocator::new(start..start + (memory.len() * 8) as u64),
        )
    };
    let revision = revision::detect(0x0080_0000).unwrap();
    Realtek {
        device,
        clock: Clock {
            ticks_per_microsecond: 1,
        },
        receive: Ring::new(&mut dma, true).unwrap(),
        transmit: Ring::new(&mut dma, true).unwrap(),
        mac: Mac([2, 0, 0, 0, 0, 1]),
        link: RuntimeLink::default(),
        revision,
        warning: None,
        function: 0,
        location: "model".into(),
        signalled,
    }
}

/// An empty receive acknowledges the pending receive and link events,
/// leaving the others, so the next one raises the vector again.
#[test]
fn empty_receive_acknowledges_the_signalled_events() {
    for signalled in [false, true] {
        let mut registers = vec![0u32; 64];
        let mut memory = vec![0u64; 262_144];
        let pending = RX_OK | LINK_CHANGE | 1 << 2;
        registers[INTERRUPT_STATUS / 4] = u32::from(pending) << 16;
        let mut net = modelled(&mut registers, &mut memory, signalled);
        net.receive.initialize(true);
        assert_eq!(net.signals(), signalled);
        assert_eq!(net.receive(), Ok(None));
        let written = (registers[INTERRUPT_STATUS / 4] >> 16) as u16;
        let acknowledged = if signalled {
            RX_OK | LINK_CHANGE
        } else {
            pending
        };
        assert_eq!(written, acknowledged);
    }
}

#[test]
fn transmit_without_carrier_is_refused_and_leaves_the_ring_untouched() {
    let mut registers = vec![0u32; 64];
    let mut memory = vec![0u64; 262_144];
    let mut net = modelled(&mut registers, &mut memory, false);
    net.transmit.initialize(false);
    let descriptors = net.transmit.descriptors.bytes().to_vec();
    assert_eq!(net.transmit(&[0; 60]), Err(LinkError::NoCarrier));
    assert_eq!(net.transmit.descriptors.bytes(), descriptors);
    assert_eq!(registers[TX_POLL / 4], 0);
}
