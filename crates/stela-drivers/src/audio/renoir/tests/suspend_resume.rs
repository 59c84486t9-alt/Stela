// SPDX-License-Identifier: GPL-2.0-only
//! Suspend resume cases.
use super::*;

#[test]
fn source_suspend_resume_keeps_same_real_ring_and_starts_a_fresh_capture_epoch() {
    use crate::audio::acp_pdm::trace_assertions::assert_ring_invalidation;
    for power_gate in [false, true] {
        let (mut controller, device, source) = ready(1, 4096);
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        let cpu = controller
            .capture
            .as_ref()
            .unwrap()
            .cpu
            .address(0, 4)
            .unwrap();
        // ready() performed exactly one original preparation.
        assert_ring_invalidation(
            &device.lock().unwrap().writes,
            IOVA,
            0x0205_0000,
            4096,
            false,
        );
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes,
            IOVA,
            0x0205_0000,
            4096,
            true,
        );
        device.lock().unwrap().advance(512);
        assert!(controller.position().unwrap().period_pending);
        controller.suspend_held_d0(power_gate).unwrap();
        assert_eq!(controller.state(), State::Suspended);
        let model = device.lock().unwrap();
        for offset in [0x2c04, 0x2c08, 0xc04, 0x1800, 0x1424, 0x1004] {
            assert_eq!(model.words[offset / 4], 0);
        }
        assert!(!model.master);
        assert_eq!(model.words[0x1420 / 4], if power_gate { 2 } else { 0 });
        assert_eq!(model.maps, 1);
        assert_eq!(model.unmaps, 0);
        assert_eq!(
            model
                .writes
                .iter()
                .filter(|entry| **entry == (0x141c, 0))
                .count(),
            usize::from(power_gate)
        );
        drop(model);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        let mut pcm = vec![0xa5; 4096];
        assert_eq!(controller.start(), Err(Error::Suspended));
        assert_eq!(controller.capture_period(&mut pcm), Err(Error::Suspended));
        assert!(pcm.iter().all(|byte| *byte == 0xa5));
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
            Err(Error::Suspended)
        );
        let restored = device.lock().unwrap().writes.len();
        controller.resume_held_d0().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[restored..],
            IOVA,
            0x0205_0000,
            4096,
            false,
        );
        assert_eq!(controller.state(), State::Prepared);
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        assert_eq!(
            controller
                .capture
                .as_ref()
                .unwrap()
                .cpu
                .address(0, 4)
                .unwrap(),
            cpu
        );
        assert_eq!(device.lock().unwrap().maps, 1);
        assert_eq!(device.lock().unwrap().words[0xc04 / 4], 0x8205_0000);
        assert_eq!(device.lock().unwrap().words[0x2c08 / 4], 0);
        assert_eq!(
            device.lock().unwrap().words[0x1804 / 4] & 0x2001_0000,
            0x2001_0000
        );
        assert_eq!(controller.capture_period(&mut pcm), Err(Error::NotPrepared));
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[restored..],
            IOVA,
            0x0205_0000,
            4096,
            true,
        );
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        assert!(pcm.iter().all(|byte| *byte == 0xa5));
        device.lock().unwrap().advance(512);
        assert_eq!(
            controller.capture_period(&mut pcm).unwrap(),
            Some(CapturePeriod {
                first_frame: 0,
                frames: 512
            })
        );
        for frame in 0..512 {
            for channel in 0..2 {
                let offset = frame * 8 + channel * 4;
                assert_eq!(
                    i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                    sample(512 + frame as u64, channel)
                );
            }
        }
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        let model = device.lock().unwrap();
        assert_eq!(model.atu_reads, 0);
        assert_eq!(
            model
                .writes
                .iter()
                .copied()
                .filter(|(offset, _)| *offset == 0xc40)
                .collect::<Vec<_>>(),
            [(0xc40, 1), (0xc40, 1)],
            "exactly one request for original preparation and one for retained PM reprogramming"
        );
    }
}

#[test]
fn failed_source_suspend_keeps_ever_published_owner_and_first_error() {
    for fault in 0..4 {
        let (mut controller, device, source) = ready(1, 4096);
        controller.start().unwrap();
        device.lock().unwrap().advance(512);
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        let expected = {
            let mut model = device.lock().unwrap();
            match fault {
                0 => {
                    model.stop_never = true;
                    Error::Timeout(Phase::DmaStop)
                }
                1 => {
                    model.reset_never = true;
                    Error::Timeout(Phase::ResetClear)
                }
                2 => {
                    model.drain_fail = true;
                    Error::Dma(DmaError::InvalidationFailed)
                }
                _ => {
                    model.ignore_write = Some(0x1424);
                    Error::RegisterRejected(CLOCK)
                }
            }
        };
        assert_eq!(controller.suspend_held_d0(false), Err(expected));
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(controller.first_error(), Some(expected));
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        assert!(controller.capture.as_ref().unwrap().published);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(controller.resume_held_d0(), Err(Error::NeedsReset));
        {
            let mut model = device.lock().unwrap();
            model.stop_never = false;
            model.reset_never = false;
            model.drain_fail = false;
            model.ignore_write = None;
        }
        controller.initialize().unwrap();
        assert_eq!(controller.state(), State::Ready);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(controller.first_error(), Some(expected));
        controller.shutdown().unwrap();
    }
}

#[test]
fn failed_resume_preserves_original_epoch_mapping_and_late_pte_effects() {
    for fault in 0..5 {
        let (mut controller, device, source) = ready(1, 4096);
        controller.start().unwrap();
        controller.suspend_held_d0(true).unwrap();
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        let writes = device.lock().unwrap().writes.len();
        let expected = {
            let mut model = device.lock().unwrap();
            match fault {
                0 => {
                    model.identity.device ^= 1;
                    Error::AuthorityChanged
                }
                1 => {
                    model.fail_after_write = Some(0x10004);
                    Error::RegisterUnavailable(0x10004)
                }
                2 => {
                    model.sync_fail = true;
                    Error::Dma(DmaError::VisibilityFailed)
                }
                3 => {
                    model.ignore_write = Some(0x1424);
                    Error::RegisterRejected(CLOCK)
                }
                _ => {
                    model.coherence_unavailable = true;
                    Error::Dma(DmaError::CoherenceUnavailable)
                }
            }
        };
        assert_eq!(controller.resume_held_d0(), Err(expected));
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(controller.first_error(), Some(expected));
        if fault == 0 {
            assert_eq!(device.lock().unwrap().writes.len(), writes);
        }
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        assert!(controller.capture.as_ref().unwrap().published);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        {
            let mut model = device.lock().unwrap();
            if fault == 0 {
                model.identity.device ^= 1;
            }
            model.sync_fail = false;
            model.ignore_write = None;
            model.coherence_unavailable = false;
        }
        controller.initialize().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(controller.first_error(), Some(expected));
        controller.shutdown().unwrap();
    }
}
