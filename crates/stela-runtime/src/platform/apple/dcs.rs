//! The DRAM channels (DCS) of an `mcc,t8112`: `/arm-io/mcc` `reg[2]`,
//! `dcs_num_channels` channels of equal stride, as the 26A434 J473AP
//! `AppleT8112MemCacheController` driver programs them:
//!
//! - `start` saves each channel's `0xec8` and `0xed0`, configuration iBoot
//!   leaves, which this boot does not program (they hold 0 until written);
//! - `handleDCSOdtsEvent` reads each channel's `0x41c` once a second: the
//!   latest LPDDR mode register 4 refresh rate of its two ranks in bits 4:0
//!   and 9:5, retrying while either reads 0xd, and hands the highest to the
//!   PMP. The model's DRAM is at nominal temperature, where LPDDR5 refreshes
//!   at the 1x rate, code 0xa (Intel 12th Generation Core datasheet volume 2,
//!   `MR4_RANK_TEMPERATURE`: "LPDDR5 1x ref rate is 0xa");
//! - `_enablePerfCtrl` and `_writePerfCtrl` write channel 0's performance
//!   counter control at `0x580`, which holds it, and `_readPerfValue` reads
//!   its counters from `0x4000`, which count no event: the model's memory
//!   is the host's;
//! - in the driver's counter table (`AMCPerfCounterConfig`, `SR
//!   duration(usec)` and `PD duration(usec)`), `0x588` bits 0 and 4 enable
//!   the self-refresh and power-down duration counters and bits 8 and 12
//!   clear them: `_enablePerfCtrl` sets a clear bit and panics unless it
//!   reads clear within 20 µs. Clearing a counter that counts nothing
//!   completes at once, so those bits read 0.
//!
//! `_dcsWriteQueueFlush` (kernel file 0x2efde44) clears low16 of each
//! channel's full32 +a40 while preserving high16. Stela hands it off zero;
//! all configuration bits retain writes. There is no queued data in this
//! coherent-memory model, so draining completes immediately.
//!
//! Every other register refuses.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::{self, Held, Span};
use alloc::vec::Vec;

const NAME: &str = "dcs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    RefreshRate,
    Held,
    /// Holds what is written except the clear bits, which complete at once.
    DurationControl,
    Counter,
}

/// The clear bits of the duration counter control.
const DURATION_CLEAR: u64 = 1 << 8 | 1 << 12;

/// The LPDDR5 1x refresh-rate code in both ranks' fields.
const NOMINAL_REFRESH: u64 = 0xa | 0xa << 5;

const CHANNEL: [Span<Role>; 8] = [
    Span::new(0x41c, 0x420, Width::Word, Role::RefreshRate),
    Span::new(0x580, 0x588, Width::Word, Role::Held),
    Span::new(0x588, 0x58c, Width::Word, Role::DurationControl),
    Span::new(0x58c, 0x640, Width::Word, Role::Held),
    Span::new(0xa40, 0xa44, Width::Word, Role::Held),
    Span::new(0xec8, 0xecc, Width::Word, Role::Held),
    Span::new(0xed0, 0xed4, Width::Word, Role::Held),
    Span::new(0x4000, 0x4060, Width::Double, Role::Counter),
];

/// Every channel, `stride` bytes apart from offset 0.
#[derive(Debug, Clone)]
pub struct Dcs {
    stride: u64,
    channels: Vec<Held>,
}

impl Dcs {
    pub fn new(channels: usize, stride: u64) -> Result<Self, &'static str> {
        if channels == 0 || stride < CHANNEL[CHANNEL.len() - 1].end {
            return Err("DCS channels do not hold their registers");
        }
        Ok(Self {
            stride,
            channels: alloc::vec![Held::default(); channels],
        })
    }

    fn locate(&self, offset: u64, width: Width) -> Result<(usize, u64, Role), &'static str> {
        let channel = usize::try_from(offset / self.stride)
            .ok()
            .filter(|&channel| channel < self.channels.len())
            .ok_or("DCS register beyond the channels")?;
        let register = offset % self.stride;
        Ok((channel, register, regfile::role(&CHANNEL, register, width)?))
    }
}

impl MmioDevice for Dcs {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let (channel, register, role) = self
            .locate(offset, width)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        Ok(match role {
            Role::RefreshRate => NOMINAL_REFRESH,
            Role::Held | Role::DurationControl => self.channels[channel].get(register),
            Role::Counter => 0,
        })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let refused = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let (channel, register, role) = self.locate(offset, width).map_err(refused)?;
        match role {
            Role::Held => {
                self.channels[channel].set(register, value);
                Ok(())
            }
            Role::DurationControl => {
                self.channels[channel].set(register, value & !DURATION_CLEAR);
                Ok(())
            }
            Role::RefreshRate | Role::Counter => Err(refused("write to a DCS status or counter")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn channels_report_nominal_refresh_and_hold_their_configuration() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut dcs = Dcs::new(8, 0x40_0000).unwrap();
        for channel in 0..8u64 {
            let at = channel * 0x40_0000;
            assert_eq!(dcs.read(at + 0x41c, Width::Word, &mut access), Ok(0x14a));
            assert_eq!(dcs.read(at + 0xed0, Width::Word, &mut access), Ok(0));
            assert_eq!(dcs.read(at + 0xa40, Width::Word, &mut access), Ok(0));
            dcs.write(at + 0xa40, Width::Word, 0xabcd_1234, &mut access)
                .unwrap();
            let value = dcs.read(at + 0xa40, Width::Word, &mut access).unwrap();
            dcs.write(at + 0xa40, Width::Word, value & 0xffff_0000, &mut access)
                .unwrap();
            assert_eq!(
                dcs.read(at + 0xa40, Width::Word, &mut access),
                Ok(0xabcd_0000)
            );
            assert!(dcs.read(at + 0xa40, Width::Double, &mut access).is_err());
            assert!(dcs.read(at + 0xa44, Width::Word, &mut access).is_err());
        }
        dcs.write(0x580, Width::Word, 0x71, &mut access).unwrap();
        assert_eq!(dcs.read(0x580, Width::Word, &mut access), Ok(0x71));
        assert_eq!(dcs.read(0x40_0580, Width::Word, &mut access), Ok(0));
        assert_eq!(dcs.read(0x4058, Width::Double, &mut access), Ok(0));
        // Clearing the duration counters completes at once.
        dcs.write(0x588, Width::Word, 0x1111, &mut access).unwrap();
        assert_eq!(dcs.read(0x588, Width::Word, &mut access), Ok(0x11));
        assert!(dcs.write(0x41c, Width::Word, 0, &mut access).is_err());
        assert!(dcs.write(0x4000, Width::Double, 0, &mut access).is_err());
        assert!(dcs.read(0x420, Width::Word, &mut access).is_err());
        assert!(dcs.read(0x200_0000, Width::Word, &mut access).is_err());
    }
}
