// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC2 entity controls and clock traversal adapted from Linux sound/usb/clock.c
//! and mixer.c. Exact reply lengths/readbacks are required; no timeout is success.
use super::{Entity, Error, Graph};
use crate::{block::BlockError, usb::xhci::setup};
use alloc::vec::Vec;

pub trait Control {
    fn control(&mut self, request: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError>;
    fn now_us(&self) -> u64;
    fn relax(&mut self);
    fn alternate(&mut self, interface: u8, alternate: u8) -> Result<(), Error> {
        let result = self.control(
            setup(1, 11, u16::from(alternate), u16::from(interface), 0),
            &[],
        )?;
        if !result.is_empty() {
            return Err(Error::ControlLength);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateRange {
    pub min: u32,
    pub max: u32,
    pub resolution: u32,
}
impl RateRange {
    pub fn contains(self, rate: u32) -> bool {
        rate >= self.min
            && rate <= self.max
            && (if self.resolution == 0 {
                rate == self.min && self.min == self.max
            } else {
                (rate - self.min).is_multiple_of(self.resolution)
            })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedClock {
    pub source: u8,
    pub numerator: u32,
    pub denominator: u32,
}
impl ResolvedClock {
    pub(super) fn source_rate(self, rate: u32) -> Result<u32, Error> {
        let n = u64::from(rate) * u64::from(self.denominator);
        if self.numerator == 0
            || self.denominator == 0
            || !n.is_multiple_of(u64::from(self.numerator))
        {
            return Err(Error::RateUnsupported);
        }
        u32::try_from(n / u64::from(self.numerator)).map_err(|_| Error::RateUnsupported)
    }
}

pub(super) fn access(bits: u32, selector: u8) -> Result<(bool, bool), Error> {
    if selector == 0 || selector > 16 {
        return Err(Error::Descriptor("UAC2 control selector"));
    }
    match (bits >> (u32::from(selector - 1) * 2)) & 3 {
        0 => Ok((false, false)),
        1 => Ok((true, false)),
        3 => Ok((true, true)),
        _ => Err(Error::Descriptor("reserved control access")),
    }
}
fn get<C: Control>(
    io: &mut C,
    interface: u8,
    entity: u8,
    selector: u8,
    channel: u8,
    request: u8,
    bytes: u16,
) -> Result<Vec<u8>, Error> {
    let reply = io.control(
        setup(
            0xa1,
            request,
            u16::from(selector) << 8 | u16::from(channel),
            u16::from(entity) << 8 | u16::from(interface),
            bytes,
        ),
        &[],
    )?;
    if reply.len() != usize::from(bytes) {
        return Err(Error::ControlLength);
    }
    Ok(reply)
}
fn set<C: Control>(
    io: &mut C,
    interface: u8,
    entity: u8,
    selector: u8,
    channel: u8,
    bytes: &[u8],
) -> Result<(), Error> {
    let reply = io.control(
        setup(
            0x21,
            1,
            u16::from(selector) << 8 | u16::from(channel),
            u16::from(entity) << 8 | u16::from(interface),
            bytes.len() as u16,
        ),
        bytes,
    )?;
    if !reply.is_empty() {
        return Err(Error::ControlLength);
    }
    Ok(())
}
fn u16_reply<C: Control>(
    io: &mut C,
    interface: u8,
    entity: u8,
    selector: u8,
) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        get(io, interface, entity, selector, 0, 1, 2)?
            .try_into()
            .unwrap(),
    ))
}

impl Graph {
    pub fn resolve_clock<C: Control>(&self, io: &mut C, id: u8) -> Result<ResolvedClock, Error> {
        let mut id = id;
        let mut visited = [false; 256];
        let mut numerator = 1u32;
        let mut denominator = 1u32;
        loop {
            if visited[usize::from(id)] {
                return Err(Error::Descriptor("cyclic clock graph"));
            }
            visited[usize::from(id)] = true;
            match self.entity(id)? {
                Entity::ClockSource { .. } => {
                    return Ok(ResolvedClock {
                        source: id,
                        numerator,
                        denominator,
                    });
                }
                Entity::ClockSelector {
                    sources, controls, ..
                } => {
                    if !access(u32::from(*controls), 1)?.0 {
                        return Err(Error::Unsupported(
                            "clock selector has no readable selection",
                        ));
                    }
                    let selected = get(io, self.control_interface, id, 1, 0, 1, 1)?[0];
                    id = *sources
                        .get(
                            usize::from(selected)
                                .checked_sub(1)
                                .ok_or(Error::ClockInvalid)?,
                        )
                        .ok_or(Error::ClockInvalid)?;
                }
                Entity::ClockMultiplier {
                    source, controls, ..
                } => {
                    if !access(u32::from(*controls), 1)?.0 || !access(u32::from(*controls), 2)?.0 {
                        return Err(Error::Unsupported(
                            "clock multiplier controls are unreadable",
                        ));
                    }
                    let n = u32::from(u16_reply(io, self.control_interface, id, 1)?);
                    let d = u32::from(u16_reply(io, self.control_interface, id, 2)?);
                    if n == 0 || d == 0 {
                        return Err(Error::ClockInvalid);
                    }
                    numerator = numerator.checked_mul(n).ok_or(Error::ClockInvalid)?;
                    denominator = denominator.checked_mul(d).ok_or(Error::ClockInvalid)?;
                    id = *source;
                }
                _ => return Err(Error::Descriptor("terminal clock is not a clock entity")),
            }
        }
    }
    pub fn clock_selection<C: Control>(&self, io: &mut C, id: u8, pin: u8) -> Result<(), Error> {
        let Entity::ClockSelector {
            sources, controls, ..
        } = self.entity(id)?
        else {
            return Err(Error::Descriptor("not a clock selector"));
        };
        if pin == 0 || usize::from(pin) > sources.len() || !access(u32::from(*controls), 1)?.1 {
            return Err(Error::Unsupported("clock selector choice is not writable"));
        }
        set(io, self.control_interface, id, 1, 0, &[pin])?;
        if get(io, self.control_interface, id, 1, 0, 1, 1)? != [pin] {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
    /// Select a descriptor-advertised signal input; pin numbering is one-based.
    pub fn signal_selection<C: Control>(&self, io: &mut C, id: u8, pin: u8) -> Result<(), Error> {
        let Entity::Selector {
            sources, controls, ..
        } = self.entity(id)?
        else {
            return Err(Error::Descriptor("not an audio signal selector"));
        };
        if pin == 0 || usize::from(pin) > sources.len() || !access(u32::from(*controls), 1)?.1 {
            return Err(Error::Unsupported("signal selector choice is not writable"));
        }
        let selector = if self.protocol == super::UAC1 { 0 } else { 1 };
        set(io, self.control_interface, id, selector, 0, &[pin])?;
        let request = if self.protocol == super::UAC1 {
            0x81
        } else {
            1
        };
        if get(io, self.control_interface, id, selector, 0, request, 1)? != [pin] {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
    pub fn ranges<C: Control>(
        &self,
        io: &mut C,
        clock: ResolvedClock,
    ) -> Result<Vec<RateRange>, Error> {
        let Entity::ClockSource { controls, .. } = self.entity(clock.source)? else {
            return Err(Error::Descriptor("not a clock source"));
        };
        if !access(u32::from(*controls), 1)?.0 {
            return Err(Error::Unsupported("clock frequency is unreadable"));
        }
        let head = get(io, self.control_interface, clock.source, 1, 0, 2, 2)?;
        let count = usize::from(u16::from_le_bytes(head.try_into().unwrap()));
        if !(1..=64).contains(&count) {
            return Err(Error::Descriptor("clock frequency range count"));
        }
        let bytes = get(
            io,
            self.control_interface,
            clock.source,
            1,
            0,
            2,
            (2 + count * 12) as u16,
        )?;
        if usize::from(u16::from_le_bytes(bytes[..2].try_into().unwrap())) != count {
            return Err(Error::ControlReadback);
        }
        let mut ranges = Vec::new();
        for entry in bytes[2..].as_chunks::<12>().0 {
            let range = RateRange {
                min: u32::from_le_bytes(entry[..4].try_into().unwrap()),
                max: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                resolution: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
            };
            if range.min == 0
                || range.max < range.min
                || (range.resolution == 0 && range.min != range.max)
            {
                return Err(Error::Descriptor("invalid clock frequency range"));
            }
            ranges.push(range);
        }
        Ok(ranges)
    }
    pub fn current_rate<C: Control>(&self, io: &mut C, clock: ResolvedClock) -> Result<u32, Error> {
        if clock.numerator == 0 || clock.denominator == 0 {
            return Err(Error::ClockInvalid);
        }
        if !matches!(self.entity(clock.source)?, Entity::ClockSource { .. }) {
            return Err(Error::ClockInvalid);
        }
        let raw = u32::from_le_bytes(
            get(io, self.control_interface, clock.source, 1, 0, 1, 4)?
                .try_into()
                .unwrap(),
        );
        let effective = u64::from(raw) * u64::from(clock.numerator);
        if raw == 0 || !effective.is_multiple_of(u64::from(clock.denominator)) {
            return Err(Error::ClockInvalid);
        }
        u32::try_from(effective / u64::from(clock.denominator)).map_err(|_| Error::ClockInvalid)
    }
    pub fn set_rate<C: Control>(
        &self,
        io: &mut C,
        clock: ResolvedClock,
        rate: u32,
    ) -> Result<(), Error> {
        if rate == 0 || rate > 768_000 {
            return Err(Error::RateUnsupported);
        }
        let source_rate = clock.source_rate(rate)?;
        if !self
            .ranges(io, clock)?
            .iter()
            .any(|r| r.contains(source_rate))
        {
            return Err(Error::RateUnsupported);
        }
        if self.current_rate(io, clock)? != rate {
            let Entity::ClockSource { controls, .. } = self.entity(clock.source)? else {
                return Err(Error::ClockInvalid);
            };
            if !access(u32::from(*controls), 1)?.1 {
                return Err(Error::RateUnsupported);
            }
            set(
                io,
                self.control_interface,
                clock.source,
                1,
                0,
                &source_rate.to_le_bytes(),
            )?;
            if self.current_rate(io, clock)? != rate {
                return Err(Error::ControlReadback);
            }
        }
        self.valid_clock(io, clock)
    }
    pub fn valid_clock<C: Control>(&self, io: &mut C, clock: ResolvedClock) -> Result<(), Error> {
        let Entity::ClockSource { controls, .. } = self.entity(clock.source)? else {
            return Err(Error::ClockInvalid);
        };
        if !access(u32::from(*controls), 2)?.0 {
            return Ok(());
        }
        let start = io.now_us();
        loop {
            match get(io, self.control_interface, clock.source, 2, 0, 1, 1)?[0] {
                1 => return Ok(()),
                0 => {}
                _ => return Err(Error::ControlReadback),
            }
            if io.now_us().saturating_sub(start) >= 100_000 {
                return Err(Error::ClockInvalid);
            }
            io.relax();
        }
    }
    fn feature(&self, id: u8, channel: u8, selector: u8, write: bool) -> Result<(), Error> {
        let Entity::Feature { controls, .. } = self.entity(id)? else {
            return Err(Error::Descriptor("not a feature unit"));
        };
        let bits = *controls.get(usize::from(channel)).ok_or(Error::Format)?;
        let access = access(bits, selector)?;
        if !access.0 || write && !access.1 {
            return Err(Error::Unsupported("feature control is absent/read-only"));
        }
        Ok(())
    }
    pub fn mute<C: Control>(&self, io: &mut C, id: u8, channel: u8) -> Result<bool, Error> {
        self.feature(id, channel, 1, false)?;
        let request = if self.protocol == super::UAC1 {
            0x81
        } else {
            1
        };
        match get(io, self.control_interface, id, 1, channel, request, 1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::ControlReadback),
        }
    }
    pub fn set_mute<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        muted: bool,
    ) -> Result<(), Error> {
        self.feature(id, channel, 1, true)?;
        set(
            io,
            self.control_interface,
            id,
            1,
            channel,
            &[u8::from(muted)],
        )?;
        if self.mute(io, id, channel)? != muted {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
    pub fn volume<C: Control>(&self, io: &mut C, id: u8, channel: u8) -> Result<i16, Error> {
        self.feature(id, channel, 2, false)?;
        let request = if self.protocol == super::UAC1 {
            0x81
        } else {
            1
        };
        Ok(i16::from_le_bytes(
            get(io, self.control_interface, id, 2, channel, request, 2)?
                .try_into()
                .unwrap(),
        ))
    }
    pub fn set_volume<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        value: i16,
    ) -> Result<(), Error> {
        self.feature(id, channel, 2, true)?;
        let ranges = if self.protocol == super::UAC1 {
            let mut values = Vec::new();
            for request in [0x82, 0x83, 0x84] {
                // UAC1 GET_MIN, GET_MAX, GET_RES
                values.extend_from_slice(&get(
                    io,
                    self.control_interface,
                    id,
                    2,
                    channel,
                    request,
                    2,
                )?);
            }
            values
        } else {
            let head = get(io, self.control_interface, id, 2, channel, 2, 2)?;
            let count = usize::from(u16::from_le_bytes(head.try_into().unwrap()));
            if !(1..=64).contains(&count) {
                return Err(Error::Descriptor("volume range count"));
            }
            let ranges = get(
                io,
                self.control_interface,
                id,
                2,
                channel,
                2,
                (2 + 6 * count) as u16,
            )?;
            if usize::from(u16::from_le_bytes(ranges[..2].try_into().unwrap())) != count {
                return Err(Error::ControlReadback);
            }
            ranges[2..].to_vec()
        };
        let mut supported = false;
        for r in ranges.as_chunks::<6>().0 {
            let min = i32::from(i16::from_le_bytes(r[..2].try_into().unwrap()));
            let max = i32::from(i16::from_le_bytes(r[2..4].try_into().unwrap()));
            let res = i32::from(u16::from_le_bytes(r[4..].try_into().unwrap()));
            if min > max || (res == 0 && min != max) {
                return Err(Error::Descriptor("volume range"));
            }
            let v = i32::from(value);
            supported |= v >= min
                && v <= max
                && (if res == 0 {
                    v == min
                } else {
                    (v - min) % res == 0
                });
        }
        if !supported {
            return Err(Error::Format);
        }
        set(
            io,
            self.control_interface,
            id,
            2,
            channel,
            &value.to_le_bytes(),
        )?;
        if self.volume(io, id, channel)? != value {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
}
