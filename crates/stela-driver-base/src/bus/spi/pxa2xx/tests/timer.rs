//! Real SSP message/CS delay paths use opaque timer intervals, not quotients.
use super::*;
struct OpaqueTime(Time);
impl crate::bus::i2c::Timer for OpaqueTime {
    fn now_us(&self) -> u64 {
        (u64::MAX - 15).wrapping_add(self.0.0.get().wrapping_mul(10)) / 10
    }
    fn start(&self) -> u64 {
        !self.0.0.get()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.0.0.get().wrapping_sub(!start)
    }
    fn relax(&self) {
        self.0.0.set(self.0.0.get() + 1);
    }
}
impl Timer for OpaqueTime {
    fn calibrated(&self) -> bool {
        true
    }
}

#[test]
fn every_ssp_layout_uses_opaque_deadlines_including_select_delays_and_fifo_exchange() {
    for profile in PROFILES {
        let (original, hardware) = host(profile);
        // No child initialization/register access has happened. Move the exact
        // original peer and clock into its alternate explicit interval service.
        let (registers, time) = original.release().ok().unwrap();
        let mut controller = Controller::new(registers, OpaqueTime(time), 10_000)
            .ok()
            .unwrap();
        controller.initialize().unwrap();
        let tx = [0x12, 0x34];
        let mut rx = [0xa5; 2];
        let mut operation = transfer(Some(&tx), Some(&mut rx), 2, 8);
        operation.delay_us = 4;
        operation.cs_change = true;
        operation.cs_change_delay_us = 3;
        let tail_tx = [0x56];
        let mut tail_rx = [0xa5];
        let tail = transfer(Some(&tail_tx), Some(&mut tail_rx), 1, 8);
        controller
            .message(
                Device {
                    loopback: true,
                    ..device()
                },
                &mut [operation, tail],
            )
            .unwrap();
        assert_eq!(rx, tx);
        assert_eq!(tail_rx, tail_tx);
        let h = hardware.borrow();
        assert_eq!(h.wire.len(), 3);
        assert!(!h.active);
        assert!(h.tx.is_empty() && h.rx.is_empty());
        assert_eq!(
            h.wire.iter().map(|f| f.tx).collect::<Vec<_>>(),
            vec![0x12, 0x34, 0x56]
        );
        drop(h);
        drop(controller.release().ok().unwrap());
        assert_eq!(hardware.borrow().drops, 1);
    }
}
