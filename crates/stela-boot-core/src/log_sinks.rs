//! The boot log's places and what losing one does.
//!
//! The boot log is a diagnostic copy of the output. A place that cannot take
//! it, at open or at a later store, closes for the rest of the boot and the
//! boot goes on: the output still reaches the serial port and the other
//! places. The user is told once per place, in plain words.

/// Where a boot log is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Log {
    /// The log region on the chosen disk's machine-state partition.
    Machine,
    /// The USB's file through the firmware, closed as boot services end.
    Firmware,
    /// The USB's file through Stela's drivers.
    Usb,
}

impl Log {
    /// The short name the log lines use.
    pub fn name(self) -> &'static str {
        match self {
            Log::Machine => "machine",
            Log::Firmware => "firmware",
            Log::Usb => "usb",
        }
    }

    /// The one line the screen shows when this place is lost.
    pub fn lost_notice(self) -> &'static str {
        match self {
            Log::Machine => {
                "The boot log on the chosen disk could not be saved. The boot goes on without it."
            }
            Log::Firmware | Log::Usb => {
                "The boot log on the USB could not be saved. The boot goes on without it."
            }
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The places lost this boot, so each is reported once.
#[derive(Debug, Default)]
pub struct Lost(u8);

impl Lost {
    /// None lost yet.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Record that `log` was lost; its notice the first time only. The
    /// firmware's and Stela's own USB file share one notice: they are the
    /// same file.
    pub fn lose(&mut self, log: Log) -> Option<&'static str> {
        let shared = match log {
            Log::Machine => log.bit(),
            Log::Firmware | Log::Usb => Log::Firmware.bit() | Log::Usb.bit(),
        };
        let first = self.0 & shared == 0;
        self.0 |= log.bit();
        first.then(|| log.lost_notice())
    }

    /// Whether `log` was lost this boot.
    pub fn is_lost(&self, log: Log) -> bool {
        self.0 & log.bit() != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_machine_log_is_reported_once() {
        let mut lost = Lost::default();
        assert_eq!(lost.lose(Log::Machine), Some(Log::Machine.lost_notice()));
        assert_eq!(lost.lose(Log::Machine), None);
        assert_eq!(lost.lose(Log::Usb), Some(Log::Usb.lost_notice()));
    }

    /// A lost log stays lost, so a later stop never points to it.
    #[test]
    fn a_lost_log_is_remembered() {
        let mut lost = Lost::default();
        assert!(!lost.is_lost(Log::Usb));
        lost.lose(Log::Usb);
        assert!(lost.is_lost(Log::Usb));
        assert!(!lost.is_lost(Log::Firmware) && !lost.is_lost(Log::Machine));
    }

    #[test]
    fn the_usb_file_is_one_place_through_either_driver() {
        let mut lost = Lost::default();
        assert!(lost.lose(Log::Firmware).is_some());
        assert_eq!(lost.lose(Log::Usb), None);
        assert_eq!(lost.lose(Log::Firmware), None);
        assert!(lost.lose(Log::Machine).is_some());
    }

    #[test]
    fn notices_are_plain_and_name_the_place() {
        assert!(Log::Machine.lost_notice().contains("chosen disk"));
        assert!(Log::Usb.lost_notice().contains("USB"));
        for log in [Log::Machine, Log::Firmware, Log::Usb] {
            assert!(log.lost_notice().contains("goes on"));
        }
    }
}
