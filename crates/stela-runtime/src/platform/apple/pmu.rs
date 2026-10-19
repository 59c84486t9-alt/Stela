//! Dialog SPMI PMU (`pmu,spmi`): a byte-addressed register file behind an
//! SPMI slave ID, holding the boot-state scratchpads and, on the primary
//! PMU, the 32768 Hz real-time clock.
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
//! `(upcount + offset) >> 15` Unix seconds. `updatePMSetting`
//! 0xfffffe0009dd44d8 read-modify-writes the byte at `info-pm_setting`.
//!
//! The model maps exactly the windows the DeviceTree names. Scratchpads,
//! fault logs and the PM setting are storage that holds the clean cold-boot
//! value zero (no faults, no wake source, no LPM state), which the driver
//! reads as such. The legacy scratchpad is 0x100 bytes, the boot keys'
//! extent rounded to the 256-byte page at whose end the RTC block begins
//! (inferred). The upcount follows the system counter and refuses writes;
//! the clock offset starts at the host's wall time when the engine knows it
//! and otherwise at zero, a PMU whose RTC lost power. Every other address
//! NACKs, as do RTC alarm enables: the model does not wake the machine.
use super::spmi::{SlaveError, SpmiSlave};
use crate::platform::apple::counter::FREQUENCY_HZ;
use alloc::vec::Vec;

/// The RTC's tick rate.
pub const RTC_HZ: u64 = 32_768;
const UPCOUNT_BYTES: u16 = 6;
const OFFSET_BYTES: u16 = 6;
/// The legacy scratchpad's extent (see the module comment).
pub const LEGACY_SCRATCH_BYTES: u16 = 0x100;

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

/// The primary PMU's RTC registers, each from its `info-rtc*` property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtc {
    pub upcount: u16,
    pub clock_offset: u16,
    pub alarm_control: u16,
    /// `info-rtc_alarm_ctrl_en_mask`: the alarm-enable bits of the control.
    pub alarm_enable: u8,
    pub alarm_offset: u16,
    pub alarm_event: u16,
    pub irq_mask: u16,
}

/// Host wall time at a system counter value, for the RTC's initial offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClock {
    pub unix_seconds: u64,
    pub counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Storage,
    Upcount(u16),
    AlarmControl,
    AlarmEvent,
}

pub struct Pmu {
    /// Storage windows, including the RTC's storage registers.
    windows: Vec<Window>,
    rtc: Option<Rtc>,
    /// Bytes of every storage window, in window order.
    storage: Vec<Vec<u8>>,
    alarm_control: u8,
    alarm_event: u8,
}

impl Pmu {
    /// `windows` are the scratchpad and log windows; the RTC adds its own.
    pub fn new(mut windows: Vec<Window>, rtc: Option<Rtc>, wall: Option<WallClock>) -> Self {
        if let Some(rtc) = rtc {
            windows.push(Window {
                base: rtc.clock_offset,
                bytes: OFFSET_BYTES,
            });
            for (base, bytes) in [(rtc.alarm_offset, 4), (rtc.irq_mask, 1)] {
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
            storage,
            alarm_control: 0,
            alarm_event: 0,
        };
        if let (Some(rtc), Some(wall)) = (rtc, wall) {
            let target = i128::from(wall.unix_seconds) * i128::from(RTC_HZ);
            let offset = (target - i128::from(ticks(wall.counter))) as i64;
            let bytes = offset.to_le_bytes();
            pmu.store(rtc.clock_offset, &bytes[..OFFSET_BYTES.into()]);
        }
        pmu
    }
    fn cell(&self, address: u16) -> Option<Cell> {
        if let Some(rtc) = self.rtc {
            if address.wrapping_sub(rtc.upcount) < UPCOUNT_BYTES {
                return Some(Cell::Upcount(address - rtc.upcount));
            }
            if address == rtc.alarm_control {
                return Some(Cell::AlarmControl);
            }
            if address == rtc.alarm_event {
                return Some(Cell::AlarmEvent);
            }
        }
        self.windows
            .iter()
            .any(|w| w.contains(address))
            .then_some(Cell::Storage)
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
    fn span(address: u16, bytes: usize) -> Result<impl Iterator<Item = u16>, SlaveError> {
        let end = u32::from(address) + bytes as u32;
        if end > 0x1_0000 {
            return Err(SlaveError::Nack);
        }
        Ok((u32::from(address)..end).map(|a| a as u16))
    }
}

/// System counter ticks as RTC ticks.
fn ticks(counter: u64) -> u64 {
    (u128::from(counter) * u128::from(RTC_HZ) / u128::from(FREQUENCY_HZ)) as u64
}

impl SpmiSlave for Pmu {
    fn read(&mut self, address: u16, data: &mut [u8], now: u64) -> Result<(), SlaveError> {
        let cells: Vec<_> = Self::span(address, data.len())?
            .map(|a| self.cell(a).map(|cell| (a, cell)))
            .collect::<Option<_>>()
            .ok_or(SlaveError::Nack)?;
        // One sample serves every upcount byte of the access.
        let raw = (ticks(now) << 1).to_le_bytes();
        for ((at, cell), out) in cells.into_iter().zip(data.iter_mut()) {
            *out = match cell {
                Cell::Storage => *self.byte(at),
                Cell::Upcount(i) => raw[usize::from(i)],
                Cell::AlarmControl => self.alarm_control,
                Cell::AlarmEvent => self.alarm_event,
            };
        }
        Ok(())
    }
    fn write(&mut self, address: u16, data: &[u8], _: u64) -> Result<(), SlaveError> {
        let cells: Vec<_> = Self::span(address, data.len())?
            .map(|a| self.cell(a).map(|cell| (a, cell)))
            .collect::<Option<_>>()
            .ok_or(SlaveError::Nack)?;
        let enable = self.rtc.map_or(0, |rtc| rtc.alarm_enable);
        for (&(_, cell), &value) in cells.iter().zip(data) {
            match cell {
                Cell::Upcount(_) => return Err(SlaveError::Nack),
                Cell::AlarmControl if value & enable != 0 => return Err(SlaveError::Nack),
                _ => {}
            }
        }
        for ((at, cell), &value) in cells.into_iter().zip(data) {
            match cell {
                Cell::Storage => *self.byte(at) = value,
                Cell::AlarmControl => self.alarm_control = value,
                // Write one to clear; no alarm event ever latches.
                Cell::AlarmEvent => self.alarm_event &= !value,
                Cell::Upcount(_) => unreachable!(),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTC: Rtc = Rtc {
        upcount: 0xf802,
        clock_offset: 0xf900,
        alarm_control: 0xf800,
        alarm_enable: 0x40,
        alarm_offset: 0xf808,
        alarm_event: 0xf80c,
        irq_mask: 0xf80e,
    };
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
        pmu.read(RTC.clock_offset, &mut off[..6], now).unwrap();
        // Sign-extend the 48-bit offset, as `_readCurrentOffsetTicks` does.
        let offset = (i64::from_le_bytes(off) << 16) >> 16;
        let seconds = (upcount as i64 + offset) >> 15;
        assert_eq!(seconds, 1_792_000_000 + 120);
        // settimeofday rewrites the offset, which then reads back.
        pmu.write(RTC.clock_offset, &[1, 2, 3, 4, 5, 6], now)
            .unwrap();
        pmu.read(RTC.clock_offset, &mut off[..6], now).unwrap();
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
        pmu.read(RTC.clock_offset, &mut off, 0).unwrap();
        assert_eq!(off, [0; 6]);
    }

    #[test]
    fn alarm_disable_is_accepted_and_alarm_enable_nacks() {
        let mut pmu = stowe(None);
        pmu.write(RTC.alarm_control, &[0], 0).unwrap();
        pmu.write(RTC.irq_mask, &[1], 0).unwrap();
        pmu.write(RTC.alarm_offset, &[1, 2, 3, 4], 0).unwrap();
        assert_eq!(
            pmu.write(RTC.alarm_control, &[0x41], 0),
            Err(SlaveError::Nack)
        );
        let mut event = [0xff];
        pmu.read(RTC.alarm_event, &mut event, 0).unwrap();
        assert_eq!(event, [0]);
        pmu.write(RTC.alarm_event, &[1], 0).unwrap();
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
    }
}
