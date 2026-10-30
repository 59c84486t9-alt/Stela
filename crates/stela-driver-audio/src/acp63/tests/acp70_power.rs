// SPDX-License-Identifier: GPL-2.0-only
//! Acp70 power cases.
use super::*;

#[test]
fn acp70_three_revisions_have_distinct_power_order_and_real_continuous_pcm_pm() {
    for revision in 0x70..=0x72 {
        let (mut controller, device, source) = fixture70(revision);
        // Low bits 1 mean transition on ACP63, but ACP70 must issue 0x1f.
        device.lock().unwrap().words[0x1028 / 4] = 1;
        controller.initialize().unwrap();
        {
            let model = device.lock().unwrap();
            let writes = &model.writes;
            let index = |entry| writes.iter().position(|actual| *actual == entry).unwrap();
            assert!(index((0x1024, 0x1f)) < index((0x1004, 1)));
            assert!(index((0x1000, 0)) < index((0x1014, 0)));
            assert!(index((0x1014, 0)) < index((0x1a00, 1)));
            assert!(index((0x1a04, 1 << 29)) < index((0x1400, 1)));
            assert!(!writes.iter().any(|(offset, _)| *offset == 0x1a08));
        }
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        controller.start().unwrap();
        let mut pcm = vec![0xa5; 4096];
        for period in 0..10 {
            device.lock().unwrap().advance(512);
            assert_eq!(
                controller.capture_period(&mut pcm).unwrap(),
                Some(CapturePeriod {
                    first_frame: period * 512,
                    frames: 512,
                })
            );
            for frame in 0..512 {
                for channel in 0..2 {
                    let offset = frame * 8 + channel * 4;
                    assert_eq!(
                        i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                        sample(period * 512 + frame as u64, channel)
                    );
                }
            }
        }
        device.lock().unwrap().writes.clear();
        controller.suspend_held_d0().unwrap();
        {
            let model = device.lock().unwrap();
            assert_eq!(model.words[0x1004 / 4], 1);
            assert_eq!(model.words[0x1014 / 4], 1);
            assert!(!model.writes.iter().any(|(offset, _)| *offset == 0x1004));
            assert_eq!(model.unmaps, 0);
        }
        controller.resume_held_d0().unwrap();
        assert_eq!(controller.state(), State::Prepared);
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        controller.start().unwrap();
        device.lock().unwrap().advance(512);
        assert_eq!(
            controller
                .capture_period(&mut pcm)
                .unwrap()
                .unwrap()
                .first_frame,
            0
        );
        assert_eq!(
            i32::from_le_bytes(pcm[..4].try_into().unwrap()),
            sample(5120, 0)
        );
        controller.shutdown().unwrap();
        assert_eq!(device.lock().unwrap().words[0x1004 / 4], 1);
        assert_eq!(device.lock().unwrap().words[0x1014 / 4], 1);
        assert_eq!(device.lock().unwrap().maps, 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn acp70_pgfsm_upper_bits_are_not_an_on_grant_and_budget_is_two_milliseconds() {
    for status in [0x1, 0x2, 0x80, 0x100] {
        let (mut controller, device, _) = fixture70(0x72);
        {
            let mut model = device.lock().unwrap();
            model.words[0x1028 / 4] = status;
            if status != 0x100 {
                // Exercise a successful request whose native effect costs
                // more than ACP63's 500us but remains within ACP70's 2ms.
                model.jump_write = Some((0x1024, 0x1f, 1500));
            }
        }
        if status == 0x100 {
            // ACP70 requests only when low eight bits are nonzero, then
            // waits for the entire status to clear; upper bits cannot pass.
            assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
            assert!(device.lock().unwrap().writes.is_empty());
            device.lock().unwrap().words[0x1028 / 4] = 0;
        } else {
            controller.initialize().unwrap();
        }
        controller.shutdown().unwrap();
    }
    for write in [false, true] {
        let (mut controller, device, _) = fixture70(0x70);
        {
            let mut model = device.lock().unwrap();
            if write {
                model.jump_write = Some((0x1024, 0x1f, 2001));
            } else {
                model.jump_read = Some((0x1028, 0, 2001));
            }
        }
        assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(offset, _)| *offset == 0x1004)
        );
        controller.shutdown().unwrap();
    }
}
