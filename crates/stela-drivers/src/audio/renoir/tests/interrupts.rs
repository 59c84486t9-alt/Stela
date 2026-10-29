// SPDX-License-Identifier: GPL-2.0-only
//! Interrupts cases.
use super::*;

#[test]
fn renoir_error_gate_order_unrelated_interrupts_and_pending_faults_are_real() {
    let (mut controller, device, source) = fixture(1);
    {
        let mut model = device.lock().unwrap();
        model.words[0x1804 / 4] = 1 << 7;
        model.words[0x1808 / 4] = 1 << 9;
    }
    controller.initialize().unwrap();
    {
        let model = device.lock().unwrap();
        // Adversarial reset retains unrelated CNTL/status; init preserves
        // both, and the actual gate precedes source error enable.
        assert_eq!(model.words[0x1808 / 4], 1 << 9);
        let gate = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1800, 1))
            .unwrap();
        let error = model
            .writes
            .iter()
            .position(|entry| *entry == (0x1804, (1 << 29) | (1 << 7)))
            .unwrap();
        assert!(gate < error);
    }
    // Start and stop preserve the unrelated IRQ bit while managing only
    // the PDM period bit.
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    device.lock().unwrap().advance(512);
    assert!(controller.position().unwrap().period_pending);
    assert_eq!(device.lock().unwrap().words[0x1808 / 4], 1 << 9);
    controller.stop().unwrap();
    assert_eq!(
        device.lock().unwrap().words[0x1804 / 4],
        (1 << 29) | (1 << 7)
    );
    // A latched actual error before restart prevents any new DMA request.
    device.lock().unwrap().words[0x1808 / 4] |= 1 << 29;
    let before = device.lock().unwrap().writes.len();
    assert_eq!(
        controller.start(),
        Err(Error::DmaFault((1 << 29) | (1 << 9)))
    );
    assert_eq!(device.lock().unwrap().writes.len(), before);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}
