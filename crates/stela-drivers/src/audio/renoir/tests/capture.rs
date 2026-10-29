// SPDX-License-Identifier: GPL-2.0-only
//! Capture cases.
use super::*;

#[test]
fn pte_capture_pcm_wraps_stop_restart_and_acknowledged_release() {
    for (revision, period) in [(1, 4096), (1, 8192), (1, 5000)] {
        let (mut controller, device, source) = ready(revision, period);
        let ring = period * 4;
        assert_eq!(controller.buffer_bytes(), Some(ring));
        let capture = controller.capture.as_ref().unwrap();
        // SAFETY: prepared DMA has never started; take CPU cache
        // ownership before poisoning, then start must hand it back.
        unsafe { capture.dma.sync_for_cpu(0..capture.cpu.bytes()) }.unwrap();
        for offset in 0..capture.cpu.bytes() {
            // SAFETY: DMA has not started; poison the CPU allocation.
            unsafe {
                capture
                    .cpu
                    .address(offset, 1)
                    .unwrap()
                    .as_ptr()
                    .write_volatile(0xa5)
            };
        }
        assert_eq!(controller.stop(), Err(Error::NotPrepared));
        assert_eq!(controller.state(), State::Prepared);
        controller.start().unwrap();
        assert_eq!(device.lock().unwrap().words[0x2c5c / 4], 0x6018);
        let mut untouched = [0xa5; 16];
        assert_eq!(
            controller.copy_stopped_ring(0, &mut untouched),
            Err(Error::Busy)
        );
        assert_eq!(untouched, [0xa5; 16]);
        // Coalesced period delivery and more than five real ring wraps.
        let frames = ring / 8 * 5 + 17;
        device.lock().unwrap().advance(frames);
        device.lock().unwrap().words[0x1808 / 4] |= 1 << 7;
        let position = controller.position().unwrap();
        assert_eq!(position.bytes, (frames * 8) as u64);
        assert_eq!(position.ring_offset, 17 * 8);
        assert!(position.period_pending);
        assert_eq!(device.lock().unwrap().words[0x1808 / 4], 1 << 7); // No unrelated W1C acknowledgement.
        controller.stop().unwrap();
        let mut pcm = vec![0; ring];
        controller.copy_stopped_ring(0, &mut pcm).unwrap();
        for (index, frame) in pcm.as_chunks::<8>().0.iter().enumerate() {
            let latest_frame = if index < 17 {
                ring / 8 * 5 + index
            } else {
                ring / 8 * 4 + index
            };
            assert_eq!(&frame[..4], sample(latest_frame as u64, 0).to_le_bytes());
            assert_eq!(&frame[4..], sample(latest_frame as u64, 1).to_le_bytes());
        }
        assert!(source.drops.load(Ordering::Relaxed) == 0);
        controller.start().unwrap();
        device.lock().unwrap().advance(10);
        controller.stop().unwrap();
        assert_eq!(controller.position().unwrap().bytes, 80);
        controller.shutdown().unwrap();
        assert_eq!(controller.state(), State::Shutdown);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert!(controller.into_stopped().is_ok());
    }
}

#[test]
fn format_geometry_and_address_ceiling_refuse_before_dma_publication() {
    let (mut controller, device, mut source) = fixture(1);
    controller.initialize().unwrap();
    let before = device.lock().unwrap().writes.len();
    for format in [
        PcmFormat {
            bits: 24,
            ..CAPTURE_FORMAT
        },
        PcmFormat {
            channels: 1,
            ..CAPTURE_FORMAT
        },
        PcmFormat {
            rate: 96_000,
            ..CAPTURE_FORMAT
        },
    ] {
        assert_eq!(
            controller.prepare_capture(&source, format, 4096),
            Err(Error::InvalidFormat)
        );
    }
    for period in [0, 4095, 4097, 8193, usize::MAX] {
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, period),
            Err(Error::InvalidBuffer)
        );
    }
    assert_eq!(device.lock().unwrap().writes.len(), before);
    source.geometry = 13;
    assert_eq!(
        controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
        Err(Error::InvalidBuffer)
    );
    assert_eq!(device.lock().unwrap().maps, 0);
    for (base, bytes, bits) in [
        (0, 4096, 40),
        (4097, 4096, 40),
        (1u64 << 40, 4096, 40),
        ((1u64 << 63) - 4096, 8192, 63),
    ] {
        assert_eq!(
            check_dma_range(base, bytes, bytes, bits),
            Err(Error::DmaAddress)
        );
    }
    assert_eq!(check_dma_range((1u64 << 63) - 4096, 4096, 4096, 63), Ok(()));
    controller.shutdown().unwrap();
}

#[test]
fn independent_counter_rollover_and_wrap_are_not_torn_or_truncated() {
    let (mut controller, device, _) = ready(1, 4096);
    device.lock().unwrap().count = u64::MAX - 15;
    controller.start().unwrap();
    device.lock().unwrap().advance(4);
    assert_eq!(controller.position().unwrap().bytes, 32);
    controller.stop().unwrap();
    device.lock().unwrap().count = 0xffff_fff8;
    controller.start().unwrap();
    device.lock().unwrap().rollover = true;
    assert_eq!(controller.position().unwrap().bytes, 8);
    device.lock().unwrap().unstable = true;
    assert_eq!(controller.position(), Err(Error::CounterUnstable));
    assert_eq!(controller.state(), State::Faulted);
    device.lock().unwrap().unstable = false;
    controller.shutdown().unwrap();
}
