//! The real controller must treat timer origins as opaque, including cleanup.
use super::*;

struct OpaqueTime {
    hardware: Time,
    origin: u64,
}
impl Timer for OpaqueTime {
    fn now_us(&self) -> u64 {
        // Independent divided counter rolls over during this three-us device
        // response. Interpreting it as a wrapping u64 microsecond clock fails.
        (u64::MAX - 15).wrapping_add(
            self.hardware
                .now_us()
                .wrapping_sub(self.origin)
                .wrapping_mul(10),
        ) / 10
    }
    fn start(&self) -> u64 {
        !self.hardware.now_us()
    }
    fn elapsed_us(&self, marker: u64) -> u64 {
        self.hardware.now_us().wrapping_sub(!marker)
    }
    fn relax(&self) {
        self.hardware.relax();
    }
}

#[test]
fn raw_opaque_markers_cross_divided_rollover_and_bound_the_actual_controller() {
    for budget in [1, 5] {
        let Fixture {
            host,
            state,
            register_drop,
            configuration_drop,
        } = fixture(0x7e22, true);
        let (raw, configuration) = host.release().ok().unwrap();
        let I801 {
            registers,
            timer,
            info,
            mut config,
            ..
        } = raw;
        config.timeout_us = budget;
        let origin = timer.now_us();
        let timer = OpaqueTime {
            hardware: timer,
            origin,
        };
        let raw = I801::new(registers, timer, info, HOST_ENABLED | CONFIG_OTHER, config).unwrap();
        // SAFETY: the original model Function/register/root owners remain
        // kept; only their explicit timer service has changed.
        let mut host = unsafe { Controller::claim(raw, configuration) }
            .ok()
            .unwrap();
        let mut value = 0xa5a5;
        let result = host.transaction(
            address(),
            Transaction::ReadWord {
                command: 0xa7,
                data: &mut value,
            },
            true,
        );
        if budget == 1 {
            assert!(matches!(result.unwrap_err().kind, ErrorKind::Timeout(_)));
            assert_eq!(value, 0xa5a5);
            assert_eq!(state.borrow().kills, 1);
        } else {
            result.unwrap();
            assert_eq!(value, 0x9876);
            assert_eq!(state.borrow().kills, 0);
            assert_eq!(state.borrow().wire.len(), 1);
        }
        assert_eq!(state.borrow().starts.len(), 1);
        assert!(!state.borrow().active);
        assert_eq!(state.borrow().registers[13], AUX_OTHER);
        drop(host.release().ok().unwrap());
        assert_eq!((register_drop.get(), configuration_drop.get()), (1, 1));
    }
}
