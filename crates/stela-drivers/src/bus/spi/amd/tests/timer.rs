//! Actual command effects remain valid across an absolute-quotient rollover.
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
fn both_command_engines_use_opaque_intervals_through_write_read_and_release() {
    for profile in [Profile::V1, Profile::V2] {
        let (original, state) = host(profile);
        let (registers, time) = original.release().ok().unwrap();
        let mut controller = Controller::new(registers, OpaqueTime(time), 10_000)
            .ok()
            .unwrap();
        controller
            .command(device(), 2, &[37, 0x91, 0x52, 0x73], &mut [])
            .unwrap();
        let mut output = [0xa5; 3];
        controller.command(device(), 3, &[37], &mut output).unwrap();
        assert_eq!(output, [0x91, 0x52, 0x73]);
        assert_eq!(state.borrow().complete, 2);
        assert_eq!(state.borrow().wire.len(), 2);
        drop(controller.release().ok().unwrap());
        assert_eq!(state.borrow().drops, 1);
    }
}
