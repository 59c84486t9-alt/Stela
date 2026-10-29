// SPDX-License-Identifier: GPL-2.0-only
//! Native clock refusal must precede config/MMIO and DMA allocation.
use super::*;

#[test]
fn invalid_native_calibration_preserves_original_packet_owner_before_all_device_effects() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        for rate in [0, u64::MAX, u64::MAX / 60_000_000 + 1] {
            let (mut previous, pages, domain, peer) = if chip == 0x0576_1000 {
                bcm5761::parts_5761(0x1680)
            } else {
                let parts = parts();
                if chip == 0x0576_2000 {
                    *parts.3.lock().unwrap() = Device::new_5762();
                }
                parts
            };
            let registers = previous.release_registers();
            // SAFETY: same original isolated peer; unavailable native timing is
            // tested before any config/MMIO or DMA admission.
            let hardware = unsafe {
                Hardware::new(
                    registers,
                    crate::Clock {
                        ticks_per_microsecond: rate,
                    },
                )
            };
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
                Ok(_) => panic!("unavailable timer admitted {chip:x} rate {rate}"),
                Err((error, packet)) => {
                    assert_eq!(error, Error::Clock);
                    packet
                }
            };
            assert!(peer.lock().unwrap().access.is_empty());
            assert_eq!(pages.allocated.get(), 0);
            assert!(domain.maps.lock().unwrap().is_empty());
            assert_eq!(peer.lock().unwrap().dma_effects, 0);
            assert!(!packet.carrier());
            assert!(packet.transmit(&[0x53; 60]).is_err());
            assert!(packet.receive().is_err());
            assert_eq!(packet.stop(), Err(Error::Clock));
            let packet = match packet.retire() {
                Ok(_) => panic!("timing refusal released the original register owner"),
                Err((error, packet)) => {
                    assert_eq!(error, Error::Clock);
                    packet
                }
            };
            drop(packet);
            assert!(peer.lock().unwrap().access.is_empty());
            assert!(domain.maps.lock().unwrap().is_empty());
            assert_eq!(peer.lock().unwrap().drops, 0);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        }
    }
}
