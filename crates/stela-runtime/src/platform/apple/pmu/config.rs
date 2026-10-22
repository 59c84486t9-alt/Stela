//! Validated byte-resource ownership for the source-qualified RTC interface.
use super::fault::FaultHistory;
use super::firmware::FirmwareHistory;
use super::{
    ClockOffset, FirmwareSram, FirmwareStartup, MAILBOX_BYTES, PmicEpoch, Retained, Rtc, Window,
};
use alloc::vec::Vec;

/// An explicit PMU register resource configuration, independent of its SID or SKU.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub(super) windows: Vec<Window>,
    pub(super) rtc: Option<Rtc>,
    pub(super) monitor: u8,
    pub(super) identity: Option<Window>,
    pub(super) mailbox: Option<[Window; 2]>,
    pub(super) fault_history: Option<FaultHistory>,
    pub(super) wake_source: Option<FaultHistory>,
    pub(super) firmware: Option<FirmwareHistory>,
    pub(super) startup: Option<FirmwareStartup>,
    pub(super) native_loader: bool,
    pub(super) execution_epoch: Option<PmicEpoch>,
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
                || (rtc.shares_event() && rtc.event_mask & (monitor | rtc.alarm_enable) != 0)
            {
                return Err("PMU RTC has empty or overlapping control masks");
            }
            if let ClockOffset::LegacyScratch(_) = rtc.clock_offset {
                let inside = |field: Window| {
                    windows.iter().any(|window| {
                        field.base >= window.base
                            && u32::from(field.base) + u32::from(field.bytes)
                                <= u32::from(window.base) + u32::from(window.bytes)
                    })
                };
                if !rtc
                    .clock_offset
                    .legacy_fields()
                    .is_some_and(|fields| fields.into_iter().all(inside))
                {
                    return Err("PMU legacy RTC offset lies outside scratch storage");
                }
            }
            occupied.extend(rtc.windows());
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
            mailbox: None,
            fault_history: None,
            wake_source: None,
            firmware: None,
            startup: None,
            native_loader: false,
            execution_epoch: None,
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

    /// Configure either retained-history owner.
    pub fn with_retained(
        self,
        kind: Retained,
        window: Window,
        initial: Vec<u8>,
    ) -> Result<Self, &'static str> {
        match kind {
            Retained::FaultLog => self.with_fault_history(window, initial),
            Retained::WakeSource => self.with_wake_source_history(window, initial),
        }
    }

    /// Configure the source's outside-scratch off-to-wake source
    /// (`info-off2wake_source`) with explicit cold or retained history.
    /// `_readOff2WakeSource` reads and acknowledges it exactly as
    /// `_readFaultLog` does its log (see `fault`); no wake producer is inferred.
    pub fn with_wake_source_history(
        mut self,
        window: Window,
        initial: Vec<u8>,
    ) -> Result<Self, &'static str> {
        let history = FaultHistory::new(window, initial)?;
        if self.wake_source.is_some() || self.occupied().any(|other| overlaps(window, other)) {
            return Err("PMU off-to-wake source duplicates or overlaps another register owner");
        }
        self.wake_source = Some(history);
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

    /// Explicitly create a stopped native Stela protected-loader owner over
    /// this configuration's actual SRAM and known startup routes. This is not
    /// an Apple reset/handoff observation or firmware execution admission.
    /// Authentication, service initialization and starting remain explicit
    /// requirements; the loader cannot manufacture a Ready value.
    pub fn with_native_firmware_loader(mut self) -> Result<Self, &'static str> {
        if self.native_loader || self.startup.is_none() || self.firmware.is_none() {
            return Err("native PMIC loader requires unique startup routes and actual SRAM");
        }
        self.native_loader = true;
        Ok(self)
    }

    /// Explicit oscillator for this actual native PMIC control/SRAM owner.
    /// This is separate from the RTC, with no inherited rate, firmware/reset
    /// observation, initialized-service or successful-execution implication.
    pub fn with_native_pmic_epoch(mut self, epoch: PmicEpoch) -> Result<Self, &'static str> {
        epoch.validate()?;
        if !self.native_loader || self.execution_epoch.is_some() {
            return Err("native PMIC execution epoch requires one actual native loader owner");
        }
        self.execution_epoch = Some(epoch);
        Ok(self)
    }

    fn occupied(&self) -> impl Iterator<Item = Window> + '_ {
        self.windows
            .iter()
            .copied()
            .chain(self.identity)
            .chain(self.mailbox.into_iter().flatten())
            .chain(self.rtc.into_iter().flat_map(|rtc| rtc.windows()))
            .chain(self.fault_history.iter().map(|history| history.window))
            .chain(self.wake_source.iter().map(|history| history.window))
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

    /// Retain the PMIC firmware mailbox (`fw-mcom-address`) and host doorbell
    /// (`fw-host-irq-address`). Their answers come from PMIC firmware, which
    /// does not execute, so every access is an explicit unsupported requirement.
    pub fn with_unqualified_firmware_mailbox(
        mut self,
        mailbox: u16,
        host_irq: u16,
    ) -> Result<Self, &'static str> {
        let windows = [
            Window {
                base: mailbox,
                bytes: MAILBOX_BYTES,
            },
            Window {
                base: host_irq,
                bytes: 1,
            },
        ];
        if self.mailbox.is_some()
            || u32::from(mailbox) + u32::from(MAILBOX_BYTES) > 0x10000
            || overlaps(windows[0], windows[1])
            || windows
                .iter()
                .any(|window| self.occupied().any(|other| overlaps(*window, other)))
        {
            return Err("PMU firmware mailbox duplicates or overlaps another register owner");
        }
        self.mailbox = Some(windows);
        Ok(self)
    }
}

pub(super) fn overlaps(a: Window, b: Window) -> bool {
    u32::from(a.base) < u32::from(b.base) + u32::from(b.bytes)
        && u32::from(b.base) < u32::from(a.base) + u32::from(a.bytes)
}
