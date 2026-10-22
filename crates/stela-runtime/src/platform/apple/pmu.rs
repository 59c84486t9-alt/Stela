//! Dialog SPMI PMU (`pmu,spmi`): a byte-addressed register file behind an
//! SPMI slave ID, holding the boot-state scratchpads and, on the primary
//! PMU service, the 32768 Hz real-time clock and its alarm. Secondary PMUs
//! can own the same register layout without owning the system service.
//! See `docs/research/pmu-t6000.md` for the independently pinned T6000 contract.
//!
//! Evidence (26A434 KC VAs, unslid): `AppleDialogSPMIPMU::_readConfiguration`
//! 0xfffffe0009dd5014 reads the `info-*` windows; `_readRegs` 0xfffffe0009dd6610
//! and `_writeRegs` 0xfffffe0009dd64d4 use SPMI extended-long reads and writes
//! of consecutive addresses; `_readBootKey`/`_writeBootKey`
//! (0xfffffe0009dd713c/0xfffffe0009dd7210) address `info-leg_scrpad` plus a key
//! offset below 0x20. `AppleDialogSPMIPMURTC::_readRTCUpcountTicks`
//! 0xfffffe0009ddee60 reads six bytes at `info-rtc` and takes the 48-bit
//! little-endian value shifted right by one as 32768 Hz ticks;
//! `_readCurrentOffsetTicks` 0xfffffe0009dddee4 and `_writeCurrentOffsetTicks`
//! 0xfffffe0009dde0d4 keep a signed 48-bit tick offset at `info-clock_offset`
//! (`<base 6>`); `getUTCTimeOfDay` 0xfffffe0009dde9e4 returns
//! `(upcount + offset) >> 15` Unix seconds. Without `info-clock_offset` (the
//! J700AP Baku primary), the RTC `_readConfiguration` (mac17p 26A434 VA
//! 0xfffffe0009a25e60..25ed4) logs "Read RTC offset from leg_scrpad" and
//! takes `info-leg_scrpad` + 4 and + 0x15 instead; `_readCurrentOffsetTicks`
//! (0xfffffe0009a264b0..2655c) reads four little-endian bytes there as the
//! offset's seconds and two bytes at + 0x15 as its 15-bit fraction (low byte,
//! then seven bits), and sign-extends `seconds << 15 | fraction` from 47
//! bits; `_writeCurrentOffsetTicks` (0xfffffe0009a2661c..266d0) writes the
//! same fields. Those bytes are legacy-scratch storage. `updatePMSetting`
//! 0xfffffe0009dd44d8 read-modify-writes the byte at `info-pm_setting`.
//!
//! The alarm (KC file offsets): `AppleDialogSPMIPMURTC::_readConfiguration`
//! (0x2dd9874) takes the alarm's registers from `info-rtc_alarm_event`,
//! `_alarm_offset`, `_irq_mask_offset` and `_alarm_ctrl`, and its bits from
//! `info-rtc_alarm_event_mask` (0x1 when absent, as on J473AP),
//! `_alarm_mask`, `_alarm_monitor_mask` and `_alarm_ctrl_en_mask`.
//! `programRTCAlarm` (0x2ddab18) clears a latched event by writing its bit
//! to the event register, writes the alarm time as four little-endian bytes
//! at the alarm offset, the alarm mask to the IRQ mask register to mask the
//! alarm's interrupt or zero to unmask it, and the monitor bit, with the
//! enable bit for an alarm, to the control register. The time is in
//! seconds of the upcount (upcount ticks >> 15): `enableDateTimeAlarm`
//! (0x2ddad80) subtracts the clock offset's seconds from a calendar time,
//! and `scheduleRTCWakeAlarm` (0x2ddb1bc) compares it with the upcount's.
//! `checkRTCWakeEvent` (0x2ddb450) reports an RTC wake when every event-mask
//! bit is set in the event register.
//!
//! The model maps explicit register owners. Ordinary scratchpads and PM
//! settings begin with declared zero storage; these are not observed Apple
//! reset values. Outside-scratch fault logs require `with_fault_history` and
//! every initial byte explicitly supplied. Only the source's complete captured
//! snapshot acknowledgement is qualified; arbitrary W1C, unqualified partial
//! writes,
//! physical fault production and reset semantics remain unsupported. A log
//! inside scratch shares its canonical bytes and source zero-clear behavior.
//! The legacy scratchpad is 0x100 bytes, the boot keys'
//! extent rounded to the 256-byte page at whose end the RTC block begins
//! (inferred). The upcount follows the system counter and refuses writes;
//! the clock offset starts at the host's wall time when the engine knows it
//! and otherwise at zero, a PMU whose RTC lost power. An enabled alarm
//! latches its event when the upcount's seconds reach the alarm time, once
//! per programming: writing the time or control arms it only for a time
//! still ahead (inferred: a comparator that fires on reaching the time, so
//! a time already passed never fires and `programRTCAlarm`'s clear of a
//! fired event does not retrigger it). The event register is
//! write-one-to-clear. The PMU's interrupt output ([`Interrupt`]) is
//! asserted while the event is latched and the IRQ mask leaves it
//! unmasked; where it leads is the board's. Every other address NACKs.
//!
//! Chapel (T603x/T604x), Abbey (M4/M5) and Woodcote declare the same byte for
//! `info-rtc_alarm_ctrl` and `info-rtc_alarm_event` (`0x2000`), with event
//! mask 0x2 beside monitor 0x1 and enable 0x40. The same `programRTCAlarm`
//! (mac15s 26A434 VA 0xfffffe0009d5f4e8) reads the event byte and, when an
//! event-mask bit is set, writes the byte it read back before it writes the
//! control (`..d5f590..d5f5d4`, `..d5f6d8..d5f70c`); `checkRTCWakeEvent`
//! (0xfffffe0009d5fe20) tests the event-mask bits of that byte. On a shared
//! byte that write-back keeps the control bits it read and clears the event
//! bits it carries, so the byte reads as control | event, its event-mask bits
//! are write-one-to-clear and its other bits are the control. The event and
//! control fields must be disjoint; the control field keeps the qualified
//! monitor / monitor+enable encodings of a separate control register.
//!
//! A PMU without RTC registers can still declare an output (`interrupts`
//! on the 26A434 Simetra, Vale, Spitfire, Portier, Club and Jerez PMUs,
//! from T8103 to T6050). The AP consumer of every PMU output is
//! `AppleDialogSPMIPMU::_interruptAction` (mac15g 26A434 VA 0xfffffe0009d63d80),
//! registered by `start` (0xfffffe0009d6317c..d6319c) for any provider with
//! `interrupts`: it only calls the RTC child's `programRTCAlarm(0)`, and with
//! no RTC child it does nothing beyond a debug log. The RTC alarm is the only
//! output source this model has; firmware, fault and rail events have no
//! modeled producer (as for the fault log), so such a PMU's output is an
//! actual, permanently deasserted wire rather than an unqualified one.
mod clock;
mod config;
mod fault;
mod firmware;
mod startup;
pub use clock::{RtcClock, RtcEpoch};
pub use config::Configuration;
pub use firmware::{FirmwareSram, FirmwareStartup};
pub use startup::PmicEpoch;

use super::spmi::{SlaveError, SpmiSlave};
#[cfg(test)]
use crate::platform::apple::counter::FREQUENCY_HZ;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;

/// The RTC's tick rate.
pub const RTC_HZ: u64 = 32_768;
/// Upcount ticks per second of the alarm's time.
const SECOND_SHIFT: u32 = 15;
const UPCOUNT_BYTES: u16 = 6;
const OFFSET_BYTES: u16 = 6;
const ALARM_BYTES: u16 = 4;
/// A legacy-scratch offset's seconds and fraction within the scratchpad.
const LEGACY_OFFSET_SECONDS: u16 = 0x4;
const LEGACY_OFFSET_FRACTION: u16 = 0x15;
/// The legacy scratchpad's extent (see the module comment).
pub const LEGACY_SCRATCH_BYTES: u16 = 0x100;
/// `AppleDialogSPMIPMURTC::_readConfiguration`'s event mask when the
/// DeviceTree gives none.
pub const DEFAULT_EVENT_MASK: u8 = 0x1;

/// A DeviceTree-named register window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub base: u16,
    pub bytes: u16,
}
impl Window {
    fn contains(&self, address: u16) -> bool {
        address >= self.base && u32::from(address) < u32::from(self.base) + u32::from(self.bytes)
    }
}

/// One PMU's RTC registers, each from its `info-rtc*` property.
/// Their presence does not imply primary system-service ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtc {
    pub upcount: u16,
    pub clock_offset: ClockOffset,
    pub alarm_control: u16,
    /// `info-rtc_alarm_ctrl_en_mask`: the alarm-enable bits of the control.
    pub alarm_enable: u8,
    pub alarm_offset: u16,
    pub alarm_event: u16,
    pub irq_mask: u16,
    /// `info-rtc_alarm_event_mask`: the event register's alarm bits.
    pub event_mask: u8,
    /// `info-rtc_alarm_mask`: the IRQ mask register's alarm bits.
    pub interrupt_mask: u8,
}

/// Where `AppleDialogSPMIPMURTC` keeps the signed calendar offset in ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOffset {
    /// `info-clock_offset=<base 6>`: a six-byte little-endian register.
    Register(u16),
    /// No `info-clock_offset`: inside the legacy scratchpad at this base, the
    /// offset's seconds as four little-endian bytes at +4 and its 15-bit
    /// fraction as two bytes at +0x15 (see the module comment).
    LegacyScratch(u16),
}

impl ClockOffset {
    /// The register's base, when the offset has its own register.
    pub fn register(self) -> Option<u16> {
        match self {
            Self::Register(base) => Some(base),
            Self::LegacyScratch(_) => None,
        }
    }

    /// The seconds and fraction fields of a legacy-scratch offset.
    fn legacy_fields(self) -> Option<[Window; 2]> {
        let Self::LegacyScratch(base) = self else {
            return None;
        };
        Some([
            Window {
                base: base.checked_add(LEGACY_OFFSET_SECONDS)?,
                bytes: 4,
            },
            Window {
                base: base.checked_add(LEGACY_OFFSET_FRACTION)?,
                bytes: 2,
            },
        ])
    }
}

impl Rtc {
    /// Chapel, Abbey and Woodcote declare one byte for the alarm control and
    /// its event (see the module comment).
    pub fn shares_event(&self) -> bool {
        self.alarm_control == self.alarm_event
    }

    /// Every register byte the RTC owns, one window per distinct register.
    /// A legacy-scratch offset is scratch storage, not an RTC register.
    fn windows(&self) -> Vec<Window> {
        let mut windows = alloc::vec![
            Window {
                base: self.upcount,
                bytes: UPCOUNT_BYTES,
            },
            Window {
                base: self.alarm_control,
                bytes: 1,
            },
            Window {
                base: self.alarm_offset,
                bytes: ALARM_BYTES,
            },
            Window {
                base: self.irq_mask,
                bytes: 1,
            },
        ];
        if !self.shares_event() {
            windows.push(Window {
                base: self.alarm_event,
                bytes: 1,
            });
        }
        if let Some(base) = self.clock_offset.register() {
            windows.push(Window {
                base,
                bytes: OFFSET_BYTES,
            });
        }
        windows
    }
}

/// Host wall time at a system counter value, for the RTC's initial offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClock {
    pub unix_seconds: u64,
    pub counter: u64,
}

/// The PMU's interrupt output, shared with whatever the board connects it
/// to: asserted while an alarm event is latched and unmasked.
#[derive(Debug, Clone, Default)]
pub struct Interrupt(Rc<Cell<bool>>);

impl Interrupt {
    pub fn asserted(&self) -> bool {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Byte {
    Storage,
    Fault(u16),
    Upcount(u16),
    AlarmControl,
    AlarmEvent,
    /// One byte holding both the control and the event bits.
    AlarmShared,
    IrqMask,
}

pub struct Pmu {
    /// Storage windows, including the RTC's storage registers.
    windows: Vec<Window>,
    rtc: Option<Rtc>,
    clock: RtcClock,
    monitor: u8,
    identity: Option<Window>,
    faults: Option<fault::FaultLog>,
    firmware: Option<firmware::FirmwareMemory>,
    startup: Option<FirmwareStartup>,
    loader: Option<startup::Loader>,
    /// Bytes of every storage window, in window order.
    storage: Vec<Vec<u8>>,
    alarm_control: u8,
    alarm_event: u8,
    /// The alarm has not fired since its time or control was last written.
    armed: bool,
    interrupt: Interrupt,
}

impl Pmu {
    /// `windows` are the scratchpad and log windows; the RTC adds its own.
    pub fn new(windows: Vec<Window>, rtc: Option<Rtc>, wall: Option<WallClock>) -> Self {
        // Original J473 legacy API; new board admission supplies the mask explicitly.
        let config = Configuration::new(windows, rtc, u8::from(rtc.is_some()))
            .expect("valid PMU register configuration");
        Self::configured(config, wall).expect("representable PMU initial wall clock")
    }

    /// Instantiate only validated byte resources. Initial wall time is a declared
    /// emulated resource value, never a captured PMIC identity or firmware image.
    pub fn configured(
        config: Configuration,
        wall: Option<WallClock>,
    ) -> Result<Self, &'static str> {
        Self::with_clock(
            config,
            RtcClock::new(RtcEpoch {
                counter: 0,
                ticks: 0,
            })?,
            wall,
        )
    }

    /// Bind a declared oscillator owner; the primary's SMC helper must retain
    /// this same handle, never derive a second epoch from its own uptime.
    pub fn with_clock(
        config: Configuration,
        clock: RtcClock,
        wall: Option<WallClock>,
    ) -> Result<Self, &'static str> {
        let Configuration {
            mut windows,
            rtc,
            monitor,
            identity,
            fault_history,
            firmware,
            startup,
            native_loader,
            execution_epoch,
        } = config;
        let loader = if native_loader {
            Some(startup::Loader::new(
                startup.expect("validated native loader profile"),
                usize::from(
                    firmware
                        .as_ref()
                        .expect("validated native SRAM")
                        .ports
                        .bytes,
                ),
                execution_epoch,
            )?)
        } else {
            None
        };
        if let Some(rtc) = rtc {
            if let Some(base) = rtc.clock_offset.register() {
                windows.push(Window {
                    base,
                    bytes: OFFSET_BYTES,
                });
            }
            for (base, bytes) in [(rtc.alarm_offset, ALARM_BYTES), (rtc.irq_mask, 1)] {
                windows.push(Window { base, bytes });
            }
        }
        let storage = windows
            .iter()
            .map(|w| alloc::vec![0; w.bytes.into()])
            .collect();
        let mut pmu = Self {
            windows,
            rtc,
            clock,
            monitor,
            identity,
            faults: fault_history.map(Into::into),
            firmware: firmware.map(Into::into),
            startup,
            loader,
            storage,
            alarm_control: 0,
            alarm_event: 0,
            armed: false,
            interrupt: Interrupt::default(),
        };
        if let (Some(rtc), Some(wall)) = (rtc, wall) {
            let upcount = pmu.clock.check(wall.counter)?;
            let target = i128::from(wall.unix_seconds) * i128::from(RTC_HZ);
            let offset = target - i128::from(upcount);
            match rtc.clock_offset {
                ClockOffset::Register(base) => {
                    if !(-(1i128 << 47)..(1i128 << 47)).contains(&offset) {
                        return Err("PMU initial RTC offset exceeds signed 48-bit resource");
                    }
                    let bytes = (offset as i64).to_le_bytes();
                    pmu.store(base, &bytes[..OFFSET_BYTES.into()]);
                }
                ClockOffset::LegacyScratch(_) => {
                    // `_readCurrentOffsetTicks` sign-extends 47 bits.
                    if !(-(1i128 << 46)..(1i128 << 46)).contains(&offset) {
                        return Err("PMU initial RTC offset exceeds signed 47-bit resource");
                    }
                    let [seconds, fraction] = rtc.clock_offset.legacy_fields().expect("validated");
                    let offset = offset as i64;
                    pmu.store(seconds.base, &((offset >> 15) as u32).to_le_bytes());
                    pmu.store(fraction.base, &[offset as u8, (offset >> 8) as u8 & 0x7f]);
                }
            }
        }
        Ok(pmu)
    }

    /// The actual retained oscillator owner, when this PMU has RTC resources.
    pub fn rtc_clock(&self) -> Option<RtcClock> {
        self.rtc.map(|_| self.clock.clone())
    }

    /// The PMU's interrupt output.
    pub fn interrupt(&self) -> Interrupt {
        self.interrupt.clone()
    }

    fn cell(&self, address: u16) -> Option<Byte> {
        if let Some(faults) = &self.faults
            && faults.window.contains(address)
        {
            return Some(Byte::Fault(address - faults.window.base));
        }
        if let Some(rtc) = self.rtc {
            if address.wrapping_sub(rtc.upcount) < UPCOUNT_BYTES {
                return Some(Byte::Upcount(address - rtc.upcount));
            }
            if address == rtc.alarm_control {
                return Some(if rtc.shares_event() {
                    Byte::AlarmShared
                } else {
                    Byte::AlarmControl
                });
            }
            if address == rtc.alarm_event {
                return Some(Byte::AlarmEvent);
            }
            if address == rtc.irq_mask {
                return Some(Byte::IrqMask);
            }
        }
        self.windows
            .iter()
            .any(|w| w.contains(address))
            .then_some(Byte::Storage)
    }
    fn byte(&mut self, address: u16) -> &mut u8 {
        let (index, window) = self
            .windows
            .iter()
            .enumerate()
            .find(|(_, w)| w.contains(address))
            .expect("storage cell");
        &mut self.storage[index][usize::from(address - window.base)]
    }
    fn store(&mut self, base: u16, bytes: &[u8]) {
        for (i, &value) in bytes.iter().enumerate() {
            *self.byte(base + i as u16) = value;
        }
    }
    fn check_identity(&self, address: u16, bytes: usize) -> Result<(), SlaveError> {
        for address in Self::span(address, bytes)? {
            if self.identity.is_some_and(|window| window.contains(address)) {
                return Err(SlaveError::Unsupported(
                    "PMU declared identity register contents are unqualified",
                ));
            }
        }
        Ok(())
    }
    fn span(address: u16, bytes: usize) -> Result<impl Iterator<Item = u16>, SlaveError> {
        let bytes = u32::try_from(bytes).map_err(|_| SlaveError::Nack)?;
        let end = u32::from(address)
            .checked_add(bytes)
            .ok_or(SlaveError::Nack)?;
        if end > 0x1_0000 {
            return Err(SlaveError::Nack);
        }
        Ok((u32::from(address)..end).map(|a| a as u16))
    }

    fn check_firmware_startup(&self, address: u16, bytes: usize) -> Result<(), SlaveError> {
        let end = u64::from(address).saturating_add(bytes.max(1) as u64);
        if self.loader.is_none()
            && self.startup.is_some_and(|profile| {
                profile.windows().iter().any(|window| {
                    u64::from(address) < u64::from(window.base) + u64::from(window.bytes)
                        && u64::from(window.base) < end
                })
            })
        {
            return Err(SlaveError::Unsupported(
                "PMU firmware startup requires the actual protected-control, execution and completion owner",
            ));
        }
        Ok(())
    }

    /// Check the shared oscillator before publishing any command effects.
    fn publish_time(&mut self, now: u64) -> Result<(), SlaveError> {
        self.check_time(now)?;
        let native = self
            .loader
            .as_mut()
            .map(|loader| loader.prepare_time(now))
            .transpose()
            .map_err(SlaveError::Unsupported)?
            .flatten();
        if self.rtc.is_some() {
            self.clock.publish(now).map_err(SlaveError::Unsupported)?;
        }
        if let Some(native) = native {
            native.commit();
        }
        self.update(now);
        Ok(())
    }

    /// The counter value at which the enabled alarm latches its event, if
    /// it is enabled, armed and has not.
    fn alarm_deadline(&mut self) -> Option<u64> {
        let rtc = self.rtc?;
        if !self.armed || self.alarm_event & rtc.event_mask != 0 {
            return None;
        }
        self.alarm_time()
    }

    /// The counter value of the enabled alarm's time.
    fn alarm_time(&mut self) -> Option<u64> {
        let rtc = self.rtc?;
        if self.alarm_control & rtc.alarm_enable == 0 {
            return None;
        }
        let mut time = [0u8; ALARM_BYTES as usize];
        for (i, byte) in time.iter_mut().enumerate() {
            *byte = *self.byte(rtc.alarm_offset + i as u16);
        }
        let upcount = u64::from(u32::from_le_bytes(time)) << SECOND_SHIFT;
        self.clock.counter_for(upcount)
    }

    /// Latch the alarm's event once its time is reached, and drive the
    /// interrupt output.
    fn update(&mut self, now: u64) {
        let Some(rtc) = self.rtc else {
            return;
        };
        if self
            .alarm_deadline()
            .is_some_and(|deadline| now >= deadline)
        {
            self.alarm_event |= rtc.event_mask;
            self.armed = false;
        }
        let masked = *self.byte(rtc.irq_mask) & rtc.interrupt_mask != 0;
        self.interrupt
            .0
            .set(self.alarm_event & rtc.event_mask != 0 && !masked);
    }
}

impl SpmiSlave for Pmu {
    fn read(&mut self, address: u16, data: &mut [u8], now: u64) -> Result<(), SlaveError> {
        self.check_identity(address, data.len())?;
        self.check_firmware_startup(address, data.len())?;
        if let Some(loader) = &self.loader
            && loader.claims(address, data.len())
        {
            let bytes = loader
                .read(address, data.len())
                .map_err(SlaveError::Unsupported)?;
            self.publish_time(now)?;
            data.copy_from_slice(&bytes);
            return Ok(());
        }
        if let Some(memory) = &self.firmware
            && memory.claims(address, data.len())
        {
            if let Some(loader) = &self.loader {
                loader
                    .check_memory(false)
                    .map_err(SlaveError::Unsupported)?;
            }
            let transfer = memory
                .prepare(address, data.len(), firmware::Direction::Read)
                .map_err(SlaveError::Unsupported)?;
            self.publish_time(now)?;
            self.firmware
                .as_mut()
                .expect("firmware owner")
                .read(transfer, data);
            return Ok(());
        }
        let cells: Vec<_> = Self::span(address, data.len())?
            .map(|a| self.cell(a).map(|cell| (a, cell)))
            .collect::<Option<_>>()
            .ok_or(SlaveError::Nack)?;
        if cells.iter().any(|(_, cell)| matches!(cell, Byte::Fault(_))) {
            self.faults
                .as_ref()
                .expect("fault owner")
                .check_read()
                .map_err(SlaveError::Unsupported)?;
        }
        self.publish_time(now)?;
        // One sample serves every upcount byte of the access.
        let raw = if self.rtc.is_some() {
            (self
                .clock
                .published_ticks()
                .map_err(SlaveError::Unsupported)?
                << 1)
                .to_le_bytes()
        } else {
            [0; 8]
        };
        for ((at, cell), out) in cells.into_iter().zip(data.iter_mut()) {
            *out = match cell {
                Byte::Storage | Byte::IrqMask => *self.byte(at),
                Byte::Fault(offset) => self.faults.as_ref().expect("fault owner").byte(offset),
                Byte::Upcount(i) => raw[usize::from(i)],
                Byte::AlarmControl => self.alarm_control,
                Byte::AlarmEvent => self.alarm_event,
                Byte::AlarmShared => self.alarm_control | self.alarm_event,
            };
        }
        if let Some(faults) = &mut self.faults {
            faults.capture(address, data.len());
        }
        Ok(())
    }
    fn write(&mut self, address: u16, data: &[u8], now: u64) -> Result<(), SlaveError> {
        self.check_identity(address, data.len())?;
        self.check_firmware_startup(address, data.len())?;
        if let Some(loader) = &self.loader
            && loader.claims(address, data.len())
        {
            let write = loader
                .prepare(
                    address,
                    data,
                    self.firmware.as_ref().expect("native loader SRAM"),
                    now,
                )
                .map_err(SlaveError::Unsupported)?;
            self.publish_time(now)?;
            let stop = matches!(write, startup::Write::Stop);
            self.loader.as_mut().expect("native loader").commit(write);
            if stop {
                self.firmware
                    .as_mut()
                    .expect("native loader SRAM")
                    .forget_address();
            }
            return Ok(());
        }
        if let Some(memory) = &self.firmware
            && memory.claims(address, data.len())
        {
            let address_byte = memory
                .check_address(address, data)
                .map_err(SlaveError::Unsupported)?;
            if let Some(loader) = &self.loader {
                // The address pair only positions the retained port. Permit
                // a new readback cursor after sealing while rejecting every
                // data mutation of the protected image.
                loader
                    .check_memory(address_byte.is_none())
                    .map_err(SlaveError::Unsupported)?;
            }
            let transfer = if address_byte.is_none() {
                Some(
                    memory
                        .prepare(address, data.len(), firmware::Direction::Write)
                        .map_err(SlaveError::Unsupported)?,
                )
            } else {
                None
            };
            self.publish_time(now)?;
            let memory = self.firmware.as_mut().expect("firmware owner");
            if let Some(byte) = address_byte {
                memory.address(address, byte);
            }
            if let Some(transfer) = transfer {
                if let Some(loader) = &mut self.loader {
                    loader.written(transfer.range.clone());
                }
                memory.write(transfer, data);
            }
            return Ok(());
        }
        let cells: Vec<_> = Self::span(address, data.len())?
            .map(|a| self.cell(a).map(|cell| (a, cell)))
            .collect::<Option<_>>()
            .ok_or(SlaveError::Nack)?;
        if cells
            .iter()
            .any(|&(_, cell)| matches!(cell, Byte::Upcount(_)))
        {
            return Err(SlaveError::Nack);
        }
        let acknowledge_faults = cells.iter().any(|(_, cell)| matches!(cell, Byte::Fault(_)));
        if acknowledge_faults {
            self.faults
                .as_ref()
                .expect("fault owner")
                .check_acknowledge(address, data)
                .map_err(SlaveError::Unsupported)?;
        }
        // Preflight the complete transfer before time, storage, event or output effects.
        if let Some(rtc) = self.rtc {
            let control = |value| value == self.monitor || value == self.monitor | rtc.alarm_enable;
            for ((_, cell), &value) in cells.iter().zip(data) {
                let qualified = match cell {
                    Byte::AlarmControl => control(value),
                    Byte::AlarmEvent => value & !rtc.event_mask == 0,
                    Byte::AlarmShared => control(value & !rtc.event_mask),
                    Byte::IrqMask => value == 0 || value == rtc.interrupt_mask,
                    _ => true,
                };
                if !qualified {
                    return Err(SlaveError::Unsupported(
                        "PMU RTC control/event/mask field is unqualified",
                    ));
                }
            }
        }
        self.publish_time(now)?;
        let alarm = self
            .rtc
            .map(|rtc| rtc.alarm_offset..rtc.alarm_offset + ALARM_BYTES);
        let mut programmed = false;
        for ((at, cell), &value) in cells.into_iter().zip(data) {
            match cell {
                Byte::Storage | Byte::IrqMask => {
                    *self.byte(at) = value;
                    programmed |= alarm.as_ref().is_some_and(|time| time.contains(&at));
                }
                Byte::AlarmControl => {
                    self.alarm_control = value;
                    programmed = true;
                }
                Byte::AlarmEvent => self.alarm_event &= !value,
                Byte::AlarmShared => {
                    let events = self.rtc.expect("RTC byte").event_mask;
                    self.alarm_control = value & !events;
                    self.alarm_event &= !(value & events);
                    programmed = true;
                }
                Byte::Fault(_) => {} // One complete snapshot is acknowledged below.
                Byte::Upcount(_) => unreachable!(),
            }
        }
        if acknowledge_faults {
            self.faults
                .as_mut()
                .expect("fault owner")
                .acknowledge(address, data.len());
        }
        if programmed {
            self.armed = self.alarm_time().is_some_and(|time| time > now);
        }
        self.update(now);
        Ok(())
    }
    fn check_time(&self, now: u64) -> Result<(), SlaveError> {
        if self.rtc.is_some() {
            self.clock
                .check(now)
                .map(|_| ())
                .map_err(SlaveError::Unsupported)?;
        }
        self.loader
            .as_ref()
            .map_or(Ok(()), |loader| loader.check_time(now))
            .map_err(SlaveError::Unsupported)
    }
    /// The RTC alarm is the only modeled output source; without an RTC the
    /// output stays deasserted (see the module comment).
    fn interrupt_level(&self) -> Option<bool> {
        Some(self.interrupt.asserted())
    }
    fn interrupt_armed(&self) -> bool {
        self.armed || self.interrupt.asserted()
    }
    fn advance(&mut self, now: u64) -> Option<u64> {
        self.publish_time(now)
            .expect("SPMI autonomous time preflight completed");
        self.alarm_deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTC: Rtc = Rtc {
        upcount: 0xf802,
        clock_offset: ClockOffset::Register(0xf900),
        alarm_control: 0xf800,
        alarm_enable: 0x40,
        alarm_offset: 0xf808,
        alarm_event: 0xf80c,
        irq_mask: 0xf80e,
        event_mask: DEFAULT_EVENT_MASK,
        interrupt_mask: 0x1,
    };
    const STOWE_OFFSET: u16 = 0xf900;
    const MAVERICK_OFFSET: u16 = 0x1411;
    fn stowe(wall: Option<WallClock>) -> Pmu {
        let windows = alloc::vec![
            Window {
                base: 0x8000,
                bytes: 0x2800
            },
            Window {
                base: 0xf700,
                bytes: LEGACY_SCRATCH_BYTES
            },
            Window {
                base: 0xf801,
                bytes: 1
            },
            Window {
                base: 0xfa00,
                bytes: 5
            },
        ];
        Pmu::new(windows, Some(RTC), wall)
    }

    pub(super) fn maverick() -> Rtc {
        Rtc {
            upcount: 0x1406,
            clock_offset: ClockOffset::Register(0x1411),
            alarm_control: 0x1401,
            alarm_enable: 0x40,
            alarm_offset: 0x140c,
            alarm_event: 0x14c0,
            irq_mask: 0x14c2,
            event_mask: 1,
            interrupt_mask: 1,
        }
    }

    #[test]
    fn configuration_unifies_storage_aliases_and_rejects_semantic_aliases_or_bad_masks() {
        let rtc = maverick();
        assert!(Configuration::new(Vec::new(), Some(rtc), 1).is_ok());
        for window in [
            Window {
                base: rtc.upcount,
                bytes: 1,
            },
            Window {
                base: 0xffff,
                bytes: 2,
            },
            Window { base: 1, bytes: 0 },
        ] {
            assert!(Configuration::new(alloc::vec![window], Some(rtc), 1).is_err());
        }
        assert!(
            Configuration::new(
                alloc::vec![
                    Window {
                        base: 0x8000,
                        bytes: 16
                    },
                    Window {
                        base: 0x800f,
                        bytes: 1
                    }
                ],
                None,
                0
            )
            .is_ok()
        );
        for invalid in [
            Rtc {
                alarm_event: rtc.irq_mask,
                ..rtc
            },
            Rtc {
                clock_offset: ClockOffset::Register(0xfffb),
                ..rtc
            },
            Rtc {
                event_mask: 0,
                ..rtc
            },
            Rtc {
                interrupt_mask: 0,
                ..rtc
            },
            Rtc {
                alarm_enable: 1,
                ..rtc
            },
        ] {
            assert!(Configuration::new(Vec::new(), Some(invalid), 1).is_err());
        }
        assert!(Configuration::new(Vec::new(), Some(rtc), 0).is_err());
        assert!(Configuration::new(Vec::new(), None, 1).is_err());
        let config = Configuration::new(
            alloc::vec![
                Window {
                    base: 0x8000,
                    bytes: 0x1000
                },
                Window {
                    base: 0x867b,
                    bytes: 16
                }
            ],
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            config.windows,
            alloc::vec![Window {
                base: 0x8000,
                bytes: 0x1000
            }]
        );
        let mut pmu = Pmu::configured(config, None).unwrap();
        pmu.write(0x867b, &[1, 2, 3], 0).unwrap();
        let mut bytes = [0; 3];
        pmu.read(0x867b, &mut bytes, 0).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        assert!(
            Pmu::configured(
                Configuration::new(Vec::new(), Some(rtc), 1).unwrap(),
                Some(WallClock {
                    unix_seconds: u64::MAX,
                    counter: 0
                })
            )
            .is_err()
        );
    }

    #[test]
    fn both_original_maverick_rtcs_have_independent_registers_without_identity_substitutes() {
        let rtc = maverick();
        let mut primary =
            Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
        let mut secondary =
            Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
        primary
            .write(MAVERICK_OFFSET, &[1, 2, 3, 4, 5, 6], 0)
            .unwrap();
        let mut data = [0xff; 6];
        secondary.read(MAVERICK_OFFSET, &mut data, 0).unwrap();
        assert_eq!(data, [0; 6]);
        secondary
            .read(rtc.upcount, &mut data, 3 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], 0, 0]) >> 1,
            3 * RTC_HZ
        );
        for pmu in [&mut primary, &mut secondary] {
            assert_eq!(pmu.read(0, &mut [0; 10], 0), Err(SlaveError::Nack));
            assert_eq!(pmu.read(0x3000, &mut [0; 16], 0), Err(SlaveError::Nack));
        }
    }

    /// The J514sAP Chapel RTC, whose control and event share one byte.
    fn chapel() -> Rtc {
        Rtc {
            upcount: 0x2002,
            clock_offset: ClockOffset::Register(0x2100),
            alarm_control: 0x2000,
            alarm_enable: 0x40,
            alarm_offset: 0x2008,
            alarm_event: 0x2000,
            irq_mask: 0x200e,
            event_mask: 0x2,
            interrupt_mask: 0x1,
        }
    }

    /// `programRTCAlarm` on a shared byte: the event write-back carries the
    /// control bits it read.
    fn program_shared(pmu: &mut Pmu, seconds: u32, now: u64) -> u8 {
        let rtc = chapel();
        let mut read = [0];
        pmu.read(rtc.alarm_event, &mut read, now).unwrap();
        if read[0] & rtc.event_mask != 0 {
            pmu.write(rtc.alarm_event, &read, now).unwrap();
        }
        if seconds != 0 {
            pmu.write(rtc.alarm_offset, &seconds.to_le_bytes(), now)
                .unwrap();
        }
        let mask = if seconds != 0 { 0 } else { rtc.interrupt_mask };
        pmu.write(rtc.irq_mask, &[mask], now).unwrap();
        let control = 0x1 | if seconds != 0 { rtc.alarm_enable } else { 0 };
        pmu.write(rtc.alarm_control, &[control], now).unwrap();
        read[0]
    }

    #[test]
    fn a_shared_control_and_event_byte_keeps_control_and_clears_written_events() {
        let rtc = chapel();
        for overlapping in [1, 0x40] {
            let bad = Rtc {
                event_mask: overlapping,
                ..rtc
            };
            assert!(Configuration::new(Vec::new(), Some(bad), 1).is_err());
        }
        let scratch = alloc::vec![Window {
            base: 0x8000,
            bytes: 0x2800
        }];
        let mut pmu =
            Pmu::configured(Configuration::new(scratch, Some(rtc), 1).unwrap(), None).unwrap();
        let output = pmu.interrupt();
        assert_eq!(program_shared(&mut pmu, 30, 0), 0);
        let mut byte = [0];
        pmu.read(rtc.alarm_control, &mut byte, 0).unwrap();
        assert_eq!(byte, [0x41]);
        // Control writes never carry an event acknowledgement by themselves.
        assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
        assert!(output.asserted());
        pmu.write(rtc.alarm_control, &[0x41], 31 * FREQUENCY_HZ)
            .unwrap();
        assert!(output.asserted());
        pmu.read(rtc.alarm_event, &mut byte, 31 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(byte, [0x43]);
        // A control field outside monitor / monitor+enable refuses whole.
        for value in [0x42, 0x02, 0x83] {
            assert!(matches!(
                pmu.write(rtc.alarm_control, &[value], 31 * FREQUENCY_HZ),
                Err(SlaveError::Unsupported(_))
            ));
        }
        assert!(output.asserted());
        // Disabling: the write-back of 0x43 clears the event, then monitor alone.
        assert_eq!(program_shared(&mut pmu, 0, 31 * FREQUENCY_HZ), 0x43);
        assert!(!output.asserted() && !pmu.interrupt_armed());
        pmu.read(rtc.alarm_control, &mut byte, 31 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(byte, [0x01]);
        // A future alarm fires once again through the same byte.
        program_shared(&mut pmu, 40, 31 * FREQUENCY_HZ);
        assert_eq!(pmu.advance(39 * FREQUENCY_HZ), Some(40 * FREQUENCY_HZ));
        assert_eq!(pmu.advance(40 * FREQUENCY_HZ), None);
        assert!(output.asserted());
    }

    /// `_readCurrentOffsetTicks`'s legacy-scratch decode.
    fn legacy_offset(pmu: &mut Pmu, base: u16, now: u64) -> i64 {
        let mut seconds = [0; 4];
        let mut fraction = [0; 2];
        pmu.read(base + 4, &mut seconds, now).unwrap();
        pmu.read(base + 0x15, &mut fraction, now).unwrap();
        let raw = u64::from(u32::from_le_bytes(seconds)) << 15
            | u64::from(fraction[1] & 0x7f) << 8
            | u64::from(fraction[0]);
        ((raw << 17) as i64) >> 17
    }

    #[test]
    fn a_legacy_scratch_clock_offset_keeps_seconds_and_fraction_in_scratch_storage() {
        // The J700AP Baku primary declares no `info-clock_offset`.
        let rtc = Rtc {
            clock_offset: ClockOffset::LegacyScratch(0xf700),
            ..RTC
        };
        let windows = || {
            alloc::vec![
                Window {
                    base: 0x8000,
                    bytes: 0x1000
                },
                Window {
                    base: 0xf700,
                    bytes: LEGACY_SCRATCH_BYTES
                },
                Window {
                    base: 0xf801,
                    bytes: 1
                },
            ]
        };
        // The fields must be existing scratch storage, never RTC registers.
        assert!(Configuration::new(windows()[..1].to_vec(), Some(rtc), 1).is_err());
        let partial = alloc::vec![Window {
            base: 0xf700,
            bytes: 0x16
        }];
        assert!(Configuration::new(partial, Some(rtc), 1).is_err());
        let wrapped = Rtc {
            clock_offset: ClockOffset::LegacyScratch(0xfff0),
            ..rtc
        };
        assert!(Configuration::new(windows(), Some(wrapped), 1).is_err());
        let wall = WallClock {
            unix_seconds: 1_792_000_000,
            counter: 5 * FREQUENCY_HZ,
        };
        let config = || Configuration::new(windows(), Some(rtc), 1).unwrap();
        let mut pmu = Pmu::configured(config(), Some(wall)).unwrap();
        let now = 125 * FREQUENCY_HZ;
        let offset = legacy_offset(&mut pmu, 0xf700, now);
        let mut up = [0u8; 8];
        pmu.read(rtc.upcount, &mut up[..6], now).unwrap();
        let upcount = (u64::from_le_bytes(up) >> 1) as i64;
        assert_eq!((upcount + offset) >> 15, 1_792_000_000 + 120);
        // No six-byte register exists beside the boot keys.
        assert_eq!(pmu.read(0xf900, &mut [0; 6], now), Err(SlaveError::Nack));
        // A negative offset (wall time behind the upcount) round-trips.
        let behind = WallClock {
            unix_seconds: 2,
            counter: 1000 * FREQUENCY_HZ,
        };
        let mut pmu = Pmu::configured(config(), Some(behind)).unwrap();
        assert_eq!(
            legacy_offset(&mut pmu, 0xf700, 0),
            (2 - 1000) * RTC_HZ as i64
        );
        let mut seconds = [0; 4];
        pmu.read(0xf704, &mut seconds, 0).unwrap();
        assert_eq!(i32::from_le_bytes(seconds), 2 - 1000);
        assert!(
            Pmu::configured(
                config(),
                Some(WallClock {
                    unix_seconds: 1 << 32,
                    counter: 0
                })
            )
            .is_err()
        );
    }

    #[test]
    fn a_pmu_without_rtc_routes_an_actual_permanently_deasserted_output() {
        use crate::platform::apple::{
            interrupt::AicInput,
            spmi::{Configuration as Controller, Profile, Spmi},
        };
        // A Vale-shaped secondary: scratch, legacy scratch, no RTC.
        let windows = alloc::vec![
            Window {
                base: 0xa000,
                bytes: 0x800
            },
            Window {
                base: 0xbb00,
                bytes: LEGACY_SCRATCH_BYTES
            },
        ];
        let mut pmu = Pmu::configured(Configuration::new(windows, None, 0).unwrap(), None).unwrap();
        let output = pmu.interrupt();
        assert_eq!(pmu.interrupt_level(), Some(false));
        assert!(!pmu.interrupt_armed());
        pmu.write(0xbb01, &[0x30], FREQUENCY_HZ).unwrap();
        assert_eq!(pmu.advance(u64::MAX / 2), None);
        assert!(!output.asserted() && !pmu.interrupt_armed());
        assert_eq!(pmu.read(0xf800, &mut [0], 0), Err(SlaveError::Nack));
        let mut spmi = Spmi::with_configuration(
            AicInput::new(0, 0x180),
            Controller::new(Profile::Gen2, 192, [256, 256]).unwrap(),
        );
        spmi.attach_with_interrupt(0xe, 2, Box::new(pmu)).unwrap();
    }

    #[test]
    fn declared_identity_is_an_explicit_requirement_and_never_zero_or_absent_readback() {
        let config = Configuration::new(Vec::new(), Some(maverick()), 1).unwrap();
        assert!(
            config
                .clone()
                .with_unqualified_identity(Window {
                    base: 0xffff,
                    bytes: 2
                })
                .is_err()
        );
        assert!(
            config
                .clone()
                .with_unqualified_identity(Window {
                    base: 0x1401,
                    bytes: 1
                })
                .is_err()
        );
        let config = config
            .with_unqualified_identity(Window { base: 0, bytes: 10 })
            .unwrap();
        assert!(
            config
                .clone()
                .with_unqualified_identity(Window { base: 16, bytes: 1 })
                .is_err()
        );
        let mut pmu = Pmu::configured(config, None).unwrap();
        let mut bytes = [0xaa; 16];
        assert!(matches!(
            pmu.read(0, &mut bytes[..10], 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(matches!(
            pmu.read(9, &mut bytes, 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(bytes, [0xaa; 16]);
        assert!(matches!(
            pmu.write(0, &[0; 10], 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(pmu.read(10, &mut bytes[..1], 0), Err(SlaveError::Nack));
    }

    #[test]
    fn rtc_controls_preflight_whole_transfer_and_preserve_due_alarm_on_refusal() {
        let rtc = maverick();
        let mut pmu =
            Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
        pmu.write(rtc.alarm_offset, &30u32.to_le_bytes(), 0)
            .unwrap();
        pmu.write(rtc.alarm_control, &[0x41], 0).unwrap();
        let output = pmu.interrupt();
        for (address, value) in [
            (rtc.alarm_control, 0),
            (rtc.alarm_control, 0x80),
            (rtc.alarm_control, 0x40),
            (rtc.irq_mask, 2),
            (rtc.alarm_event, 2),
        ] {
            assert!(matches!(
                pmu.write(address, &[value], 31 * FREQUENCY_HZ),
                Err(SlaveError::Unsupported(_))
            ));
            assert!(!output.asserted());
            assert!(pmu.armed);
        }
        assert_eq!(
            pmu.write(rtc.alarm_offset, &[99; 6], 31 * FREQUENCY_HZ),
            Err(SlaveError::Nack)
        );
        assert!(pmu.armed);
        assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
        assert!(output.asserted());
        // Masking changes the wire without discarding the latched wake event.
        pmu.write(rtc.irq_mask, &[1], 31 * FREQUENCY_HZ).unwrap();
        assert!(!output.asserted());
        let mut event = [0];
        pmu.read(rtc.alarm_event, &mut event, 31 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [1]);
        pmu.write(rtc.irq_mask, &[0], 31 * FREQUENCY_HZ).unwrap();
        assert!(output.asserted());
        pmu.write(rtc.alarm_event, &[1], 31 * FREQUENCY_HZ).unwrap();
        assert!(!output.asserted());
    }

    #[test]
    fn unqualified_upcount_wrap_refuses_before_read_write_or_autonomous_effects() {
        let mut pmu = stowe(None);
        let now = (1u128 << 47) * u128::from(FREQUENCY_HZ) / u128::from(RTC_HZ);
        let now = u64::try_from(now).unwrap();
        let mut data = [0xaa; 6];
        assert!(matches!(
            pmu.read(RTC.upcount, &mut data, now),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(data, [0xaa; 6]);
        assert!(matches!(
            pmu.write(STOWE_OFFSET, &[0xaa; 6], now),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(matches!(
            pmu.check_time(now),
            Err(SlaveError::Unsupported(_))
        ));
        pmu.read(STOWE_OFFSET, &mut data, 0).unwrap();
        assert_eq!(data, [0; 6]);
    }

    #[test]
    fn wall_time_follows_upcount_plus_offset_at_32768_hz() {
        let wall = WallClock {
            unix_seconds: 1_792_000_000,
            counter: 5 * FREQUENCY_HZ,
        };
        let mut pmu = stowe(Some(wall));
        let now = 125 * FREQUENCY_HZ;
        let mut up = [0u8; 6];
        pmu.read(RTC.upcount, &mut up, now).unwrap();
        let mut raw = [0u8; 8];
        raw[..6].copy_from_slice(&up);
        let upcount = u64::from_le_bytes(raw) >> 1;
        assert_eq!(upcount, 125 * RTC_HZ);
        let mut off = [0u8; 8];
        pmu.read(STOWE_OFFSET, &mut off[..6], now).unwrap();
        // Sign-extend the 48-bit offset, as `_readCurrentOffsetTicks` does.
        let offset = (i64::from_le_bytes(off) << 16) >> 16;
        let seconds = (upcount as i64 + offset) >> 15;
        assert_eq!(seconds, 1_792_000_000 + 120);
        // settimeofday rewrites the offset, which then reads back.
        pmu.write(STOWE_OFFSET, &[1, 2, 3, 4, 5, 6], now).unwrap();
        pmu.read(STOWE_OFFSET, &mut off[..6], now).unwrap();
        assert_eq!(off[..6], [1, 2, 3, 4, 5, 6]);
        assert_eq!(pmu.write(RTC.upcount, &[0], now), Err(SlaveError::Nack));
    }

    #[test]
    fn boot_keys_and_pm_setting_are_storage_and_unnamed_addresses_nack() {
        let mut pmu = stowe(None);
        pmu.write(0xf701, &[0x30], 0).unwrap();
        let mut keys = [0xffu8; 0x20];
        pmu.read(0xf700, &mut keys, 0).unwrap();
        assert_eq!(keys[1], 0x30);
        assert!(keys.iter().enumerate().all(|(i, &b)| i == 1 || b == 0));
        pmu.write(0xf801, &[0x04], 0).unwrap();
        let mut fault = [0xffu8; 5];
        pmu.read(0xfa00, &mut fault, 0).unwrap();
        assert_eq!(fault, [0; 5]);
        // The window ends at 0xfa05; a straddling access changes nothing.
        assert_eq!(pmu.write(0xfa04, &[1, 1], 0), Err(SlaveError::Nack));
        pmu.read(0xfa04, &mut fault[..1], 0).unwrap();
        assert_eq!(fault[0], 0);
        assert_eq!(pmu.read(0x1234, &mut [0], 0), Err(SlaveError::Nack));
        // Without the host's wall time the RTC reads the Unix epoch.
        let mut off = [0xffu8; 6];
        pmu.read(STOWE_OFFSET, &mut off, 0).unwrap();
        assert_eq!(off, [0; 6]);
    }

    /// `programRTCAlarm`'s writes for an alarm at upcount second `seconds`,
    /// or for none.
    fn program(pmu: &mut Pmu, seconds: u32, now: u64) {
        let mut event = [0];
        pmu.read(RTC.alarm_event, &mut event, now).unwrap();
        if event[0] & RTC.event_mask != 0 {
            pmu.write(RTC.alarm_event, &[RTC.event_mask], now).unwrap();
        }
        let enabled = seconds != 0;
        pmu.write(RTC.alarm_offset, &seconds.to_le_bytes(), now)
            .unwrap();
        let mask = if enabled { 0 } else { RTC.interrupt_mask };
        pmu.write(RTC.irq_mask, &[mask], now).unwrap();
        let control = 0x1 | if enabled { RTC.alarm_enable } else { 0 };
        pmu.write(RTC.alarm_control, &[control], now).unwrap();
    }

    #[test]
    fn an_enabled_alarm_latches_its_event_at_its_second_and_interrupts_until_cleared() {
        let mut pmu = stowe(None);
        let interrupt = pmu.interrupt();
        // No alarm: nothing to wait for.
        program(&mut pmu, 0, 0);
        assert_eq!(pmu.advance(0), None);
        // An alarm at upcount second 30 fires at 30 s of the counter.
        program(&mut pmu, 30, FREQUENCY_HZ);
        assert_eq!(pmu.advance(FREQUENCY_HZ), Some(30 * FREQUENCY_HZ));
        assert!(!interrupt.asserted());
        assert_eq!(pmu.advance(30 * FREQUENCY_HZ - 1), Some(30 * FREQUENCY_HZ));
        assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
        assert!(interrupt.asserted());
        let mut event = [0];
        pmu.read(RTC.alarm_event, &mut event, 30 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [RTC.event_mask]);
        // Disabling it clears the event and masks the interrupt.
        program(&mut pmu, 0, 31 * FREQUENCY_HZ);
        assert!(!interrupt.asserted());
        pmu.read(RTC.alarm_event, &mut event, 31 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [0]);
        // A time already passed never fires.
        program(&mut pmu, 10, 40 * FREQUENCY_HZ);
        assert_eq!(pmu.advance(40 * FREQUENCY_HZ), None);
        pmu.read(RTC.alarm_event, &mut event, 40 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [0]);
        // A masked alarm still latches its event, without interrupting.
        program(&mut pmu, 50, 49 * FREQUENCY_HZ);
        pmu.write(RTC.irq_mask, &[RTC.interrupt_mask], 49 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(pmu.advance(50 * FREQUENCY_HZ), None);
        pmu.read(RTC.alarm_event, &mut event, 50 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [RTC.event_mask]);
        assert!(!interrupt.asserted());
        // Cleared, a fired alarm stays quiet until it is programmed again.
        pmu.write(RTC.alarm_event, &[RTC.event_mask], 51 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(pmu.advance(51 * FREQUENCY_HZ), None);
        pmu.read(RTC.alarm_event, &mut event, 51 * FREQUENCY_HZ)
            .unwrap();
        assert_eq!(event, [0]);
        // A PMU without an RTC has no RTC registers.
        let mut aux = Pmu::new(
            alloc::vec![Window {
                base: 0xa000,
                bytes: 0x800
            }],
            None,
            None,
        );
        assert_eq!(aux.read(0xf802, &mut [0; 6], 0), Err(SlaveError::Nack));
        aux.write(0xa7ff, &[9], 0).unwrap();
        assert_eq!(aux.advance(0), None);
    }
    #[test]
    #[ignore = "requires pinned original mac13j26A434 via STELA_TEST_PMGR_M1_KERNELCACHE"]
    fn original_primary_service_rtc_registers_alarm_and_edge_contract_are_source_pinned() {
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        for (offset, bytes, digest) in [
            (
                0x2d53facusize,
                208usize,
                "aa7a73fd15abdeaf204380645aaedc18c853dd98711ce169dd673d845ad5f2c7",
            ), // fault-log-count
            (
                0x1c85b2cusize,
                224usize,
                "da1639c284a54128a62d241ebf9b3f5b35aa9b0d924ccf18fffd28cfdb0a591f",
            ), // spmi-long-wrappers
            (
                0x2d54ee4usize,
                632usize,
                "31e6d88dbfb049d96923baaa68e1568e5231b59a30416c638502105b0fc1d599",
            ), // pmu-read-write-and-retry
            (
                0x2d4e5c4usize,
                12usize,
                "ed122dab0fa82ceea645c8407ec5262eaca8bb5c6dc6d2127a6624ac6da06d93",
            ), // controller-mode
            (
                0x2d4e7acusize,
                372usize,
                "fe52ab77e84967db2b65e3507219bc51ea23fd0d0d04e28802c2b425766257eb",
            ), // controller-chunk-lengths
            (
                0x2d55cf4usize,
                492usize,
                "9589a8ab2afc9a41eb886446c9fc1e9f6b6e3cdccf48f521dbd5c16e3593b7dc",
            ), // complete-fault-log-consumer
            (
                0x2d53a24usize,
                184usize,
                "39f5200f3b2267cdae8f5e29ec5d4293b8e4c2957625cee6a2394b388c2e8469",
            ), // configuration-required-legacy
            (
                0x2d549acusize,
                40usize,
                "27e91094d85bd53f6ca5bb1df7fea2f5d6600c66522fcea9a1e9e8902ca09608",
            ), // configuration-return
            (
                0x2d51480usize,
                3632usize,
                "dbc14082608594c40cd85664786a97447e03b3c6453605450af9070c3b83a636",
            ), // start
            (
                0x2d55b4cusize,
                424usize,
                "2cf8402d36132ecec69eb4e2fdb17acf52827f5bb9b8363d2969351859261541",
            ), // boot-key
            (
                0x2d552f8usize,
                1216usize,
                "f6a80ac867c834d37f1e75c71a9f4b0d908ef3bac3193b1f0490019ae4c990fe",
            ), // memory
            (
                0x2d5a504usize,
                12usize,
                "185b69410ba1e6bd9bbd267500bfbd9aaf87eb4672710113c02ff2e99c98a9da",
            ), // handle-start
            (
                0x1c86618usize,
                1632usize,
                "a0c1723a9e9570b8d979edbf58c64a4b085de86afba8e66c1f5c2a9858ebd18b",
            ), // user-client
            (
                0x2d53b00usize,
                96usize,
                "ae72f04d836556710cd8623bf9b2363ef48d1cab10996e739e0062175178d32c",
            ), // primary-configuration
            (
                0x2d51b78usize,
                76usize,
                "fe0fd661e1a7e0cb7a9b73341ecfdb78b602f2e3d2379b57125d872a1ce033b4",
            ), // primary-registration
            (
                0x2d5b4b4usize,
                428usize,
                "eb7dfdd469a93045a2973ead2831e79b91c2710c899f60791612ae12aac8b160",
            ), // rtc-primary-start
            (
                0x2d523fcusize,
                88usize,
                "6cdf10ae91af7d453a6b7d2f5d526e3c92f248ec99ac90f98b0a93d136d8df5c",
            ), // rtc-alarm-interrupt-action
            (
                0x2d5d528usize,
                616usize,
                "4daed85c0f254899e551d039561acca4c1bd0bdd12ba90dc87cfb279482812ea",
            ), // rtc-program
            (
                0x2d5da14usize,
                104usize,
                "a9ee1c7e106e4d2333a784c35233fc407dfefd4826290a38e1a71439e9695c86",
            ), // rtc-upcount
            (
                0x2d5c284usize,
                2028usize,
                "78c4fcde5203af89991b24a4afe42b85f930e87177c434051e4d192b7e632e02",
            ), // rtc-register-configuration
            (
                0x2d5dbccusize,
                420usize,
                "4e6176a07847a9d3425fa88b7cb61875c4fd955e8db99d379c5a84db0c448fec",
            ), // rtc-schedule
            (
                0x2d5de60usize,
                132usize,
                "8e624bf9b2d4bc205e9ef306279804737a3ad6e613d0b71b32a99e8183b5d493",
            ), // rtc-read-wake-event
            (
                0x12a6e18usize,
                8usize,
                "3e0e0067b1027e83b92ef97507faea7580ffed3c5bbcb72e63c5a9876b4499f4",
            ), // spmi-get-vector-type-slot
            (
                0x54821a4usize,
                8usize,
                "2f6110664dbd16b514a0c2c7c8326932a36e85d2f15b91e57ca76efd2c7a625a",
            ), // spmi-edge-handler
            (
                0x12a8ff0usize,
                8usize,
                "628c0e30cbecff297891396eb57936a4b8e6df7e493b51fd2bdd52fb9f721b41",
            ), // rtc-alarm-vtable-slot
            (
                0x2d51864usize,
                80usize,
                "77649b1296a66d2725fe2bc3c1b607b70fa6f9d2c6da9f0dcf661cdeacdd014b",
            ), // identity-descriptor-retain
        ] {
            assert_eq!(
                crate::sha256(&data[offset..offset + bytes]),
                digest,
                "source span {offset:#x}"
            );
        }
        // A missing legacy descriptor branches directly to the false return,
        // before the later ID-descriptor retention and register initialization.
        let required = u32::from_le_bytes(data[0x2d53a9c..0x2d53aa0].try_into().unwrap());
        assert_eq!(required & 0xff00_001f, 0xb400_0000); // CBZ X0
        let displacement = (((required >> 5) & 0x7ffff) as i32) << 13 >> 11;
        assert_eq!(0x2d53a9c_i64 + i64::from(displacement), 0x2d549ac);
        let handle_start = u64::from_le_bytes(data[0x12a8260..0x12a8268].try_into().unwrap());
        assert_eq!(
            0xfffffe0007004000 + (handle_start & 0x3fffffff),
            0xfffffe0009d5e504
        );
        assert_eq!(
            &data[0x2d5a508..0x2d5a510],
            &[0x20, 0, 0x80, 0x52, 0xc0, 3, 0x5f, 0xd6] // MOV W0, #1; RET
        );
        let edge = u64::from_le_bytes(data[0x12a6e18..0x12a6e20].try_into().unwrap());
        assert_eq!(0xfffffe0007004000 + (edge & 0x3fffffff), 0xfffffe000c4861a4);
        assert_eq!(
            &data[0x54821a4..0x54821ac],
            &[0, 0, 128, 82, 192, 3, 95, 214]
        );
        let alarm = u64::from_le_bytes(data[0x12a8ff0..0x12a8ff8].try_into().unwrap());
        assert_eq!(
            0xfffffe0007004000 + (alarm & 0x3fffffff),
            0xfffffe0009d61528
        );
    }

    #[test]
    #[ignore = "requires original J314s26A434 DT via STELA_TEST_SPMI_DT"]
    fn original_j314s_two_rtc_resources_have_one_primary_service_and_local_output() {
        use crate::machine::adt::Node;
        let data = std::fs::read(std::env::var("STELA_TEST_SPMI_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let mut pmus = 0;
        let mut rtcs = 0;
        let mut primaries = 0;
        for controller in root.child("arm-io").unwrap().children().unwrap() {
            if !controller.compatible("aapl,spmi") {
                continue;
            }
            for node in controller.children().unwrap() {
                if !node.compatible("pmu,spmi") {
                    continue;
                }
                pmus += 1;
                assert_eq!(node.cells32("info-id").unwrap(), [0, 10]); // address/length, not ID bytes
                // The original AP driver requires legacy scratch before retaining
                // this descriptor. Monaco remains a provider without that service;
                // neither property grants identity-byte readback semantics.
                if node.compatible("pmu,maverick") {
                    assert_eq!(node.first_u32("info-leg_scrpad"), Some(0x6000));
                    assert_eq!(
                        node.cells32("info-fw-sram").unwrap(),
                        [0xc830, 0xc831, 0xc833, 0x3000, 16]
                    );
                    assert!(node.property("has-socd-fw-sram").is_none());
                } else {
                    assert!(node.compatible("pmu,monaco"));
                    assert!(node.property("info-leg_scrpad").is_none());
                    assert!(node.property("info-fw-sram").is_none());
                }
                let mut windows = Vec::new();
                for key in ["info-scrpad", "info-fault_shadow"] {
                    if let Some(pair) = node.cells32(key) {
                        windows.push(Window {
                            base: pair[0] as u16,
                            bytes: pair[1] as u16,
                        });
                    }
                }
                if let Some(base) = node.first_u32("info-leg_scrpad") {
                    windows.push(Window {
                        base: base as u16,
                        bytes: LEGACY_SCRATCH_BYTES,
                    });
                }
                if let Some(base) = node.first_u32("info-pm_setting") {
                    windows.push(Window {
                        base: base as u16,
                        bytes: 1,
                    });
                }
                let rtc = if node.first_u32("info-rtc").is_some() {
                    rtcs += 1;
                    let expected = maverick();
                    for (key, value) in [
                        ("info-rtc", expected.upcount),
                        ("info-rtc_alarm_ctrl", expected.alarm_control),
                        ("info-rtc_alarm_offset", expected.alarm_offset),
                        ("info-rtc_alarm_event", expected.alarm_event),
                        ("info-rtc_irq_mask_offset", expected.irq_mask),
                    ] {
                        assert_eq!(node.first_u32(key), Some(u32::from(value)));
                    }
                    assert_eq!(node.cells32("info-clock_offset").unwrap(), [0x1411, 6]);
                    assert_eq!(node.first_u32("info-rtc_alarm_monitor_mask"), Some(1));
                    assert_eq!(node.first_u32("info-rtc_alarm_ctrl_en_mask"), Some(64));
                    assert_eq!(node.first_u32("info-rtc_alarm_mask"), Some(1));
                    Some(expected)
                } else {
                    None
                };
                let log = node.cells32("info-fault_log").unwrap();
                let log = Window {
                    base: log[0] as u16,
                    bytes: log[1] as u16,
                };
                assert_eq!(log.base, 0x1000);
                assert_eq!(log.bytes, if rtc.is_some() { 10 } else { 1 });
                let configuration = Configuration::new(windows, rtc, u8::from(rtc.is_some()))
                    .unwrap()
                    // This fixture declares empty virtual history, not an Apple
                    // reset value or the live reference Mac's fault state.
                    .with_fault_history(log, alloc::vec![0; usize::from(log.bytes)])
                    .unwrap()
                    .with_unqualified_identity(Window { base: 0, bytes: 10 })
                    .unwrap();
                let mut model = Pmu::configured(configuration, None).unwrap();
                let mut history = alloc::vec![0xff; usize::from(log.bytes)];
                model.read(log.base, &mut history, 0).unwrap();
                assert!(history.iter().all(|&byte| byte == 0));
                model.write(log.base, &history, 0).unwrap();
                assert!(matches!(
                    model.read(0, &mut [0; 10], 0),
                    Err(SlaveError::Unsupported(_))
                ));
                if node.first_u32("is-primary") == Some(1) {
                    primaries += 1;
                    assert!(rtc.is_some());
                    assert_eq!(node.cells32("interrupts").unwrap(), [2]);
                    assert_eq!(
                        node.first_u32("interrupt-parent"),
                        controller.first_u32("AAPL,phandle")
                    );
                } else {
                    assert!(node.property("interrupts").is_none());
                }
            }
        }
        assert_eq!((pmus, rtcs, primaries), (5, 2, 1));
    }
}
