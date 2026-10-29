// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics notices: ../synaptics.rs and input/THIRD_PARTY.md.
//! ForcePad selection and sustained-pressure state from the Synaptics driver.
//! The caller supplies the native firmware identifier; packet bits alone
//! cannot distinguish a ForcePad from a conventional touchpad.
pub(super) fn matches(firmware_id: &str) -> bool {
    firmware_id.strip_prefix("PNP: ").is_some_and(|ids| {
        ids.split(' ')
            .any(|id| id.eq_ignore_ascii_case("SYN300D") || id.eq_ignore_ascii_case("SYN3014"))
    })
}

#[derive(Default)]
pub(super) struct State {
    start_us: Option<u64>,
    reported: bool,
}
impl State {
    pub(super) fn update(&mut self, pressure: u8, width: u8, above: bool, now_us: u64) -> bool {
        if pressure == 0 {
            *self = Self::default();
        } else if width >= 4 && above {
            if let Some(start) = self.start_us {
                // Source time_after is strict. The native monotonic timer uses
                // microseconds, without claiming a Linux scheduler tick rate.
                if now_us.wrapping_sub(start) > 50_000 {
                    self.reported = true;
                }
            } else {
                self.start_us = Some(now_us);
            }
        } else {
            self.start_us = None;
        }
        self.reported
    }
}
