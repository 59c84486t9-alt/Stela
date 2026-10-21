//! Validated byte-resource ownership for the source-qualified RTC interface.
use super::fault::FaultHistory;
use super::firmware::FirmwareHistory;
use super::{ALARM_BYTES, FirmwareSram, FirmwareStartup, OFFSET_BYTES, Rtc, UPCOUNT_BYTES, Window};
use alloc::vec::Vec;

/// An explicit PMU register resource configuration, independent of its SID or SKU.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub(super) windows: Vec<Window>,
    pub(super) rtc: Option<Rtc>,
    pub(super) monitor: u8,
    pub(super) identity: Option<Window>,
    pub(super) fault_history: Option<FaultHistory>,
    pub(super) firmware: Option<FirmwareHistory>,
    pub(super) startup: Option<FirmwareStartup>,
}

impl Configuration {
    /// Storage aliases are normalized to one byte owner; RTC masks describe the
    /// recovered monitor/enable, event-W1C and interrupt-mask fields only.
    pub fn new(windows: Vec<Window>, rtc: Option<Rtc>, monitor: u8) -> Result<Self, &'static str> {
        let mut extents = Vec::<(u32, u32)>::new();
        for window in windows {
            let end = u32::from(window.base) + u32::from(window.bytes);
            if window.bytes == 0 || end > 0x10000 {
                return Err("PMU storage resource is empty or exceeds 16 bits");
            }
            extents.push((u32::from(window.base), end));
        }
        extents.sort_unstable();
        let mut union = Vec::<(u32, u32)>::new();
        for (base, end) in extents {
            if let Some(last) = union.last_mut()
                && base <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                union.push((base, end));
            }
        }
        let mut windows = Vec::new();
        for (mut base, end) in union {
            while base < end {
                let bytes = (end - base).min(u32::from(u16::MAX));
                windows.push(Window {
                    base: base as u16,
                    bytes: bytes as u16,
                });
                base += bytes;
            }
        }
        let mut occupied = windows.clone();
        if let Some(rtc) = rtc {
            if monitor == 0
                || rtc.alarm_enable == 0
                || monitor & rtc.alarm_enable != 0
                || rtc.event_mask == 0
                || rtc.interrupt_mask == 0
            {
                return Err("PMU RTC has empty or overlapping control masks");
            }
            occupied.extend([
                Window {
                    base: rtc.upcount,
                    bytes: UPCOUNT_BYTES,
                },
                Window {
                    base: rtc.clock_offset,
                    bytes: OFFSET_BYTES,
                },
                Window {
                    base: rtc.alarm_control,
                    bytes: 1,
                },
                Window {
                    base: rtc.alarm_offset,
                    bytes: ALARM_BYTES,
                },
                Window {
                    base: rtc.alarm_event,
                    bytes: 1,
                },
                Window {
                    base: rtc.irq_mask,
                    bytes: 1,
                },
            ]);
        } else if monitor != 0 {
            return Err("PMU without RTC has an RTC monitor mask");
        }
        occupied.sort_unstable_by_key(|window| window.base);
        let mut end = 0;
        for window in occupied {
            let next = u32::from(window.base) + u32::from(window.bytes);
            if window.bytes == 0 || next > 0x10000 || u32::from(window.base) < end {
                return Err("PMU register resources are empty, overlapping or exceed 16 bits");
            }
            end = next;
        }
        Ok(Self {
            windows,
            rtc,
            monitor,
            identity: None,
            fault_history: None,
            firmware: None,
            startup: None,
        })
    }
    /// Configure the source's outside-scratch fault log with explicit cold or
    /// retained history. No Apple reset value or physical fault producer is
    /// inferred. A log inside scratch must remain that canonical storage owner.
    pub fn with_fault_history(
        mut self,
        window: Window,
        initial: Vec<u8>,
    ) -> Result<Self, &'static str> {
        let history = FaultHistory::new(window, initial)?;
        if self.fault_history.is_some() || self.occupied().any(|other| overlaps(window, other)) {
            return Err("PMU fault log duplicates or overlaps another register owner");
        }
        self.fault_history = Some(history);
        Ok(self)
    }

    /// Bind real retained SRAM bytes to the AP address/data ports. This grants
    /// no firmware execution, control/status, silicon identity or reset state.
    pub fn with_firmware_sram(
        mut self,
        ports: FirmwareSram,
        initial: Vec<u8>,
    ) -> Result<Self, &'static str> {
        let history = FirmwareHistory::new(ports, initial)?;
        if self.firmware.is_some()
            || ports
                .windows()
                .iter()
                .any(|window| self.occupied().any(|other| overlaps(*window, other)))
        {
            return Err("PMU firmware SRAM duplicates or overlaps another register owner");
        }
        self.firmware = Some(history);
        Ok(self)
    }

    /// Preserve the source's startup routes as explicit missing execution
    /// requirements; never map reset/configuration/status to plain storage.
    pub fn with_unqualified_firmware_startup(
        mut self,
        profile: FirmwareStartup,
    ) -> Result<Self, &'static str> {
        if self.startup.is_some()
            || profile
                .windows()
                .iter()
                .any(|window| self.occupied().any(|other| overlaps(*window, other)))
        {
            return Err("PMU firmware startup duplicates or overlaps another register owner");
        }
        self.startup = Some(profile);
        Ok(self)
    }

    fn occupied(&self) -> impl Iterator<Item = Window> + '_ {
        self.windows
            .iter()
            .copied()
            .chain(self.identity)
            .chain(self.rtc.into_iter().flat_map(|rtc| {
                [
                    Window {
                        base: rtc.upcount,
                        bytes: UPCOUNT_BYTES,
                    },
                    Window {
                        base: rtc.clock_offset,
                        bytes: OFFSET_BYTES,
                    },
                    Window {
                        base: rtc.alarm_control,
                        bytes: 1,
                    },
                    Window {
                        base: rtc.alarm_offset,
                        bytes: ALARM_BYTES,
                    },
                    Window {
                        base: rtc.alarm_event,
                        bytes: 1,
                    },
                    Window {
                        base: rtc.irq_mask,
                        bytes: 1,
                    },
                ]
            }))
            .chain(self.fault_history.iter().map(|history| history.window))
            .chain(
                self.firmware
                    .iter()
                    .flat_map(|history| history.ports.windows()),
            )
            .chain(
                self.startup
                    .into_iter()
                    .flat_map(|profile| profile.windows().iter().copied()),
            )
    }
    /// Retain the source's identity register extent without fabricating silicon
    /// identity bytes. Access stops explicitly until that separate contract exists.
    pub fn with_unqualified_identity(mut self, identity: Window) -> Result<Self, &'static str> {
        let end = u32::from(identity.base) + u32::from(identity.bytes);
        if identity.bytes == 0 || end > 0x10000 || self.identity.is_some() {
            return Err("PMU identity extent is empty, duplicated or exceeds 16 bits");
        }
        if self.occupied().any(|window| overlaps(identity, window)) {
            return Err("PMU identity overlaps another register owner");
        }
        self.identity = Some(identity);
        Ok(self)
    }
}

pub(super) fn overlaps(a: Window, b: Window) -> bool {
    u32::from(a.base) < u32::from(b.base) + u32::from(b.bytes)
        && u32::from(b.base) < u32::from(a.base) + u32::from(a.bytes)
}
