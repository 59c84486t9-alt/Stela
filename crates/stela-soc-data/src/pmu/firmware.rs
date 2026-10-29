//! Immutable PMIC startup routes, AP SRAM ports and supplied initial bytes.
use super::Window;
use alloc::vec::Vec;
pub const WINDOW_BYTES: u16 = 16;
/// Known original AP startup register routes whose device-side effects have
/// not yet been qualified. Binding one makes accesses explicit requirements,
/// never bus NACKs or apparently healthy storage/status values. This grants no
/// firmware execution or identity; callers qualify the actual resource family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareStartup {
    Maverick,
    Monaco,
}
impl FirmwareStartup {
    pub fn windows(self) -> &'static [Window] {
        match self {
            Self::Maverick => &[
                Window {
                    base: 0xc800,
                    bytes: 3,
                }, // stop + metadata
                Window {
                    base: 0xc804,
                    bytes: 4,
                }, // configure + start + source post-upload control
                Window {
                    base: 0xc813,
                    bytes: 1,
                }, // startup status
                Window {
                    base: 0xc828,
                    bytes: 1,
                }, // mode
                Window {
                    base: 0x7000,
                    bytes: 5,
                }, // protected command
            ],
            Self::Monaco => &[
                Window {
                    base: 0x2800,
                    bytes: 3,
                },
                Window {
                    base: 0x2804,
                    bytes: 4,
                },
                Window {
                    base: 0x2814,
                    bytes: 1,
                },
                Window {
                    base: 0x1404,
                    bytes: 1,
                }, // revision-dependent mode route
                Window {
                    base: 0x50e6,
                    bytes: 1,
                },
                Window {
                    base: 0x50eb,
                    bytes: 1,
                },
                Window {
                    base: 0x5000,
                    bytes: 5,
                },
            ],
        }
    }
}

/// The five `info-fw-sram` cells. These describe AP ports and capacity, not
/// firmware identity, an initial cursor, untouched bytes or a running PMIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSram {
    pub address_low: u16,
    pub address_high: u16,
    pub data: u16,
    pub bytes: u16,
    pub chunk: u16,
}

impl FirmwareSram {
    pub fn windows(self) -> [Window; 3] {
        [
            Window {
                base: self.address_low,
                bytes: 1,
            },
            Window {
                base: self.address_high,
                bytes: 1,
            },
            Window {
                base: self.data,
                bytes: WINDOW_BYTES,
            },
        ]
    }

    pub fn validate(self) -> Result<(), &'static str> {
        if self.bytes == 0 || self.chunk != WINDOW_BYTES {
            return Err(
                "PMU firmware SRAM requires a nonempty capacity and qualified 16-byte window",
            );
        }
        let windows = self.windows();
        for (i, a) in windows.iter().enumerate() {
            if u32::from(a.base) + u32::from(a.bytes) > 0x10000
                || windows[..i]
                    .iter()
                    .any(|b| super::configuration::overlaps(*a, *b))
            {
                return Err("PMU firmware SRAM ports overlap or exceed 16 bits");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FirmwareHistory {
    pub ports: FirmwareSram,
    initial: Vec<u8>,
}
impl FirmwareHistory {
    pub fn new(ports: FirmwareSram, initial: Vec<u8>) -> Result<Self, &'static str> {
        ports.validate()?;
        if initial.len() != usize::from(ports.bytes) {
            return Err("PMU firmware SRAM requires every initial byte explicitly supplied");
        }
        Ok(Self { ports, initial })
    }
}

impl FirmwareHistory {
    /// Transfer the supplied initial SRAM bytes without any live cursor or execution state.
    pub fn into_parts(self) -> (FirmwareSram, Vec<u8>) {
        (self.ports, self.initial)
    }
}
