// SPDX-License-Identifier: GPL-2.0-or-later
//! Fractional frame scheduling and explicit feedback. The common
//! denominator represents nominal rates and Q16.16 feedback per frame or
//! microframe exactly.
use super::{Error, Format};

/// Frames times 8000 microframes per second times 8192.
const PHASE_DENOMINATOR: u64 = 65_536_000;
const HIGH_SPEED: u8 = 3;

pub(super) struct Packetizer {
    phase: u64,
    frequency: u64,
    rate: u32,
    /// `ep->freqshift`: how far feedback is shifted from Q16.16, once the
    /// first value has shown it.
    shift: Option<i32>,
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
        let frequency = u64::from(rate) * 8192;
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
            rate,
            shift: None,
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
    /// Linux `snd_usb_handle_sync_urb`. Feedback should be Q16.16 samples
    /// per microframe at high speed and 10.14 per frame at full speed, but
    /// devices differ, so the first value fixes its shift by moving it
    /// within -25%..+50% of the nominal rate. A value from -12.5% of nominal
    /// to `freqmax` sets the rate; any other is ignored and the shift is
    /// detected again. A short or zero value is ignored.
    pub(super) fn feedback(&mut self, bytes: &[u8], speed: u8) {
        let mut f = match bytes.len() {
            0..3 => return,
            3 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]),
            _ => u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 0x0fff_ffff,
        };
        if f == 0 {
            return;
        }
        // get_usb_high_speed_rate and get_usb_full_speed_rate: Q16.16 per
        // microframe or frame.
        let (nominal, microframes) = match speed {
            HIGH_SPEED => (((self.rate << 10) + 62) / 125, 1),
            _ => (((self.rate << 13) + 62) / 125, 8),
        };
        match self.shift {
            None => {
                let mut shift = 0;
                while f < nominal - nominal / 4 {
                    f <<= 1;
                    shift += 1;
                }
                while f > nominal + nominal / 2 {
                    f >>= 1;
                    shift -= 1;
                }
                self.shift = Some(shift);
            }
            Some(shift) if shift >= 0 => f <<= shift,
            Some(shift) => f >>= -shift,
        }
        // freqmax: +50%, unless wMaxPacketSize holds fewer frames per packet.
        let interval = (self.service / microframes).max(1);
        let mut maximum = nominal + (nominal >> 1);
        if (((u64::from(maximum) * u64::from(interval)) + 0xffff) >> 16) > self.maximum as u64 {
            maximum = ((self.maximum as u64) << 16) as u32 / interval;
        }
        if f >= nominal - nominal / 8 && f <= maximum {
            self.frequency = u64::from(f) * PHASE_DENOMINATOR / 65_536 / u64::from(microframes);
        } else {
            self.shift = None;
        }
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
            cluster_id: None,
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
            pitch: None,
        }
    }
    #[test]
    fn odd_full_speed_feedback_preserves_low_fraction_bit() {
        let mut f = format();
        f.service_microframes = 8;
        let mut p = Packetizer::new(&f, 48_000).unwrap();
        let raw = (48u32 << 14) + 1;
        p.feedback(&raw.to_le_bytes()[..3], 1);
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
    fn feedback_format_is_detected_like_snd_usb_handle_sync_urb() {
        let f = format();
        let mut p = Packetizer::new(&f, 48_000).unwrap();
        let frames = |p: &mut Packetizer| {
            (0..8).map(|_| p.next_bytes().unwrap()).sum::<usize>() / f.frame_bytes()
        };
        // A high-speed device reporting 10.14: shifted up by two, +1/8.
        p.feedback(&((6u32 << 14) + (6 << 11)).to_le_bytes(), 3);
        assert_eq!(p.shift, Some(2));
        assert_eq!(frames(&mut p), 54);
        // Zero and short values change nothing.
        p.feedback(&[0; 4], 3);
        p.feedback(&[1, 0], 3);
        assert_eq!(frames(&mut p), 54);
        // Past freqmax (+50%) the value is ignored and the shift redetected.
        p.feedback(&(10u32 << 14).to_le_bytes(), 3);
        assert_eq!(p.shift, None);
        assert_eq!(frames(&mut p), 54);
        p.feedback(&(6u32 << 16).to_le_bytes(), 3);
        assert_eq!((p.shift, frames(&mut p)), (Some(0), 48));
    }
}
