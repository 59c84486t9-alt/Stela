// SPDX-License-Identifier: GPL-2.0-or-later
//! Fractional frame scheduling and standard explicit feedback. The common
//! denominator represents both nominal rates and USB 16.16 feedback exactly.
use super::{Error, Format};

const PHASE_DENOMINATOR: u64 = 16_384_000;

pub(super) struct Packetizer {
    phase: u64,
    frequency: u64,
    nominal: u64,
    service: u32,
    maximum: usize,
    frame_bytes: usize,
    fill_max: bool,
}
impl Packetizer {
    pub(super) fn new(format: &Format, rate: u32) -> Result<Self, Error> {
        if !(1..=32).contains(&format.channels)
            || !(1..=4).contains(&format.subslot)
            || format.bits == 0
            || format.bits > format.subslot * 8
            || format.service_microframes == 0
        {
            return Err(Error::Format);
        }
        let frequency = u64::from(rate) * 2048;
        let maximum = format.max_bytes / format.frame_bytes();
        if rate == 0
            || maximum == 0
            || !format.max_bytes.is_multiple_of(format.frame_bytes()) && format.fill_max
            || (frequency * u64::from(format.service_microframes)).div_ceil(PHASE_DENOMINATOR)
                > maximum as u64
        {
            return Err(Error::Format);
        }
        Ok(Self {
            phase: 0,
            frequency,
            nominal: frequency,
            service: format.service_microframes,
            maximum,
            frame_bytes: format.frame_bytes(),
            fill_max: format.fill_max,
        })
    }
    pub(super) fn next_bytes(&mut self) -> Result<usize, Error> {
        self.phase = self
            .phase
            .checked_add(self.frequency * u64::from(self.service))
            .ok_or(Error::Feedback)?;
        let frames = self.phase / PHASE_DENOMINATOR;
        self.phase %= PHASE_DENOMINATOR;
        if frames > self.maximum as u64 {
            return Err(Error::Feedback);
        }
        Ok(if self.fill_max {
            self.maximum
        } else {
            frames as usize
        } * self.frame_bytes)
    }
    pub(super) fn feedback(&mut self, bytes: &[u8], speed: u8) -> Result<(), Error> {
        let frequency = match (speed, bytes.len()) {
            (3, 4) => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())) * 250,
            (1, 3) => u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])) * 125,
            _ => return Err(Error::Feedback),
        };
        self.frequency(frequency)
    }

    fn frequency(&mut self, frequency: u64) -> Result<(), Error> {
        if frequency == 0
            || frequency < self.nominal - self.nominal / 8
            || frequency > self.nominal + self.nominal / 8
            || (frequency * u64::from(self.service)).div_ceil(PHASE_DENOMINATOR)
                > self.maximum as u64
        {
            return Err(Error::Feedback);
        }
        self.frequency = frequency;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audio::Direction,
        usb::{audio::Sync, xhci::Endpoint},
    };
    fn format() -> Format {
        Format {
            power_domain: None,
            endpoint_rates: None,
            interface: 1,
            alternate: 1,
            terminal: 1,
            clock: 10,
            direction: Direction::Playback,
            channels: 2,
            subslot: 4,
            bits: 24,
            channel_config: 3,
            data: Endpoint {
                address: 1,
                attributes: 5,
                max_packet: 1024,
                interval: 1,
                companion: None,
            },
            sync: Sync::Synchronous,
            service_microframes: 1,
            max_bytes: 1024,
            fill_max: false,
        }
    }
    #[test]
    fn odd_full_speed_feedback_preserves_low_fraction_bit() {
        let mut f = format();
        f.service_microframes = 8;
        let mut p = Packetizer::new(&f, 48_000).unwrap();
        let raw = (48u32 << 14) + 1;
        p.feedback(&raw.to_le_bytes()[..3], 1).unwrap();
        let bytes: usize = (0..16384).map(|_| p.next_bytes().unwrap()).sum();
        assert_eq!(bytes, ((48 * 16384 + 1) * f.frame_bytes()));
    }
    #[test]
    fn fractional_pcm_accounts_every_frame() {
        let f = format();
        for rate in [44_100, 48_000, 96_000, 192_000] {
            let mut p = Packetizer::new(&f, rate).unwrap();
            let bytes: usize = (0..8000).map(|_| p.next_bytes().unwrap()).sum();
            assert_eq!(bytes, rate as usize * f.frame_bytes());
        }
    }
    #[test]
    fn feedback_is_bounded_and_does_not_change_container_alignment() {
        let f = format();
        let mut p = Packetizer::new(&f, 48_000).unwrap();
        p.feedback(&(6u32 << 16).to_le_bytes(), 3).unwrap();
        assert_eq!(p.next_bytes().unwrap(), 48);
        assert_eq!(p.feedback(&[0; 4], 3), Err(Error::Feedback));
        assert_eq!(
            p.feedback(&(12u32 << 16).to_le_bytes(), 3),
            Err(Error::Feedback)
        );
        assert_eq!(p.feedback(&[0; 3], 3), Err(Error::Feedback));
    }
}
