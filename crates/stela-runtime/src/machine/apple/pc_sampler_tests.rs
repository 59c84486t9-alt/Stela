//! The actual board sampler selects and latches only its four-byte trigger.
use super::AppleDevices;
use crate::platform::apple::coresight::PC_SAMPLE;
use stela_engine::machine::Devices;

#[test]
fn pc_sampler_routes_only_triggers_and_preserves_the_latched_sample() {
    let base = 0x2_1004_0000;
    let register = base + PC_SAMPLE;
    let mut devices = AppleDevices::new();
    devices.add_coresight_sampler(1, base).unwrap();
    assert_eq!(devices.pc_sample_target(register, 8), None);
    assert_eq!(devices.pc_sample_target(register, 4), Some(1));
    assert_eq!(devices.read(0, register, 8, 0), Ok(0));
    devices.observe_pc_sample(register, 0x1000);
    devices.read(0, register, 4, 0).unwrap();
    assert_eq!(devices.read(0, register, 8, 0), Ok(0x1000));
    assert_eq!(devices.read(0, register, 8, 0), Ok(0x1000));
    devices.observe_pc_sample(register, 0x2000);
    devices.read(0, register, 4, 0).unwrap();
    assert_eq!(devices.read(0, register, 8, 0), Ok(0x2000));
}
