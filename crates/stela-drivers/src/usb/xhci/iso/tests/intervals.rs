// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous intervals fixtures.
use super::*;

#[test]
fn ist_encoding_and_endpoint_intervals() {
    for ist in 0..16 {
        for exponent in 0..=12 {
            let mut dma = TestRegion::new(32 * 1024 * 8);
            let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
            c.iso_caps = Capabilities::new(0x110, ist, 1 << 11);
            let mut ep = endpoint(0x81, HIGH_SPEED);
            ep.interval = exponent + 1;
            c.configure(1, &[ep], None, &mut dma).unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            model.borrow_mut().mfindex = 0;
            if exponent == 0 {
                // Independently enumerated last too-close full frame for
                // each raw HCSParams2 IST nibble, including frame units.
                let too_close = [8, 8, 8, 8, 8, 8, 8, 16, 8, 16, 24, 32, 40, 48, 56, 64];
                assert_schedule_refused(&mut c, &model, buffer.physical(), too_close[ist as usize]);
            }
            let first = c
                .submit_iso_scheduled(1, 3, buffer.physical(), 32, IsoSchedule::AtMicroframe(4096))
                .unwrap();
            // Advance the peer clock, keeping the first TD, so
            // even the longest admitted interval fits the future window.
            model.borrow_mut().mfindex = 3840;
            let next = 4096 + (1 << exponent);
            let second = c
                .submit_iso_scheduled(
                    1,
                    3,
                    buffer.physical() + 32,
                    32,
                    IsoSchedule::AtMicroframe(next),
                )
                .unwrap();
            model.borrow_mut().service_at(3, 4096, SUCCESS);
            model.borrow_mut().service_at(3, u32::from(next), SUCCESS);
            assert_eq!(c.completed_iso(&first).unwrap().unwrap().bytes, 32);
            assert_eq!(c.completed_iso(&second).unwrap().unwrap().bytes, 32);
            assert_eq!(&buffer.bytes()[..64], &[0x5a; 64]);
        }
    }
}

#[test]
fn cfc_admission_and_asap_fallback() {
    let mut dma = TestRegion::new(32 * 1024 * 8);
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, false);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    c.submit_iso_scheduled(1, 3, buffer.physical(), 32, IsoSchedule::AtMicroframe(32))
        .unwrap();
    assert_schedule_refused(&mut c, &model, buffer.physical(), 33);
    let next = c.submit_iso(1, 3, buffer.physical() + 32, 32).unwrap();
    assert_eq!(next.schedule(), IsoSchedule::Asap);
    assert_ne!(model.borrow().active[1].1.control & SIA, 0);
}
