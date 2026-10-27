// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC2 entity controls and clock traversal adapted from Linux sound/usb/clock.c
//! and mixer.c. Exact reply lengths are required; no timeout is success.
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
    /// The terminal's bCSourceID, which Linux keys clock sharing on.
    pub terminal: u8,
    pub source: u8,
}
/// MAX_NR_RATES.
const MAX_RATES: usize = 1024;
/// A source's rates as Linux `parse_uac2_sample_rate_range` announces them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rates {
    /// The first resolution-1 range: SNDRV_PCM_RATE_CONTINUOUS.
    Continuous { min: u32, max: u32 },
    /// The rate table, at most MAX_NR_RATES long.
    Table(Vec<u32>),
}
impl Rates {
    pub fn contains(&self, rate: u32) -> bool {
        match self {
            Self::Continuous { min, max } => (*min..=*max).contains(&rate),
            Self::Table(rates) => rates.contains(&rate),
        }
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
pub(super) fn get<C: Control>(
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
pub(super) fn set<C: Control>(
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
impl Graph {
    /// The clock source behind terminal clock `id`, as Linux
    /// `set_sample_rate_v2v3` finds it: a valid source first, switching a
    /// writable selector to another valid input when needed; otherwise the
    /// current path unvalidated, since an external clock may only become
    /// valid at the new rate. The rate change validates again.
    pub fn resolve_clock<C: Control>(&self, io: &mut C, id: u8) -> Result<ResolvedClock, Error> {
        match self.find_clock(io, id, id, &mut [false; 256], true) {
            Ok(clock) => Ok(clock),
            Err(_) => self.find_clock(io, id, id, &mut [false; 256], false),
        }
    }
    /// Linux `__uac_clock_find_source` with automatic clock selection.
    /// Multipliers pass through, as in Linux.
    fn find_clock<C: Control>(
        &self,
        io: &mut C,
        terminal: u8,
        id: u8,
        visited: &mut [bool; 256],
        validate: bool,
    ) -> Result<ResolvedClock, Error> {
        if core::mem::replace(&mut visited[usize::from(id)], true) {
            return Err(Error::Descriptor("cyclic clock graph"));
        }
        match self.entity(id)? {
            Entity::ClockSource { .. } => {
                if validate && !self.source_valid(io, terminal, id) {
                    return Err(Error::ClockInvalid);
                }
                Ok(ResolvedClock {
                    terminal,
                    source: id,
                })
            }
            Entity::ClockSelector {
                sources, controls, ..
            } => {
                let pins = sources.len();
                let writable = access(u32::from(*controls), 1)?.1;
                // One input needs no read; an unreadable selector is still
                // read, Linux only warning about it.
                let current = if pins == 1 {
                    Some(1)
                } else {
                    get(io, self.control_interface, id, 1, 0, 1, 1)
                        .ok()
                        .map(|value| usize::from(value[0]))
                        .filter(|pin| (1..=pins).contains(pin))
                };
                if let Some(pin) = current {
                    let found = self.find_clock(io, terminal, sources[pin - 1], visited, validate);
                    if found.is_ok() && writable {
                        match self.clock_selection(io, id, pin as u8) {
                            Ok(()) => {}
                            // A one-input selector's refusal is a firmware bug.
                            Err(_) if pins == 1 => {}
                            Err(error) => return Err(error),
                        }
                    }
                    if found.is_ok() || !validate {
                        return found;
                    }
                }
                if !writable {
                    return Err(Error::ClockInvalid);
                }
                for pin in (1..=pins).filter(|pin| Some(*pin) != current) {
                    let Ok(clock) = self.find_clock(io, terminal, sources[pin - 1], visited, true)
                    else {
                        continue;
                    };
                    if self.clock_selection(io, id, pin as u8).is_ok() {
                        return Ok(clock);
                    }
                }
                Err(Error::ClockInvalid)
            }
            Entity::ClockMultiplier { source, .. } => {
                self.find_clock(io, terminal, *source, visited, validate)
            }
            _ => Err(Error::Descriptor("terminal clock is not a clock entity")),
        }
    }
    /// Linux `uac_clock_source_is_valid`: assumed valid without a readable
    /// validity control, invalid when the read fails, otherwise nonzero.
    fn source_valid<C: Control>(&self, io: &mut C, terminal: u8, source: u8) -> bool {
        let Ok(Entity::ClockSource {
            attributes,
            controls,
            ..
        }) = self.entity(source)
        else {
            return false;
        };
        if !access(u32::from(*controls), 2).is_ok_and(|(readable, _)| readable) {
            return true;
        }
        match get(io, self.control_interface, source, 2, 0, 1, 1) {
            Err(_) => false,
            Ok(value) if value[0] != 0 => true,
            // `uac_clock_source_is_valid_quirk`: a UAC2 internal source wired
            // straight to the terminal with a single rate is valid anyway.
            Ok(_) => {
                self.protocol == super::UAC2
                    && terminal == source
                    && attributes & 3 != 0
                    && self
                        .rates(io, ResolvedClock { terminal, source })
                        .is_ok_and(|rates| matches!(rates, Rates::Table(rates) if rates.len() == 1))
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
    /// The source's frequency ranges. Like Linux
    /// `parse_uac2_sample_rate_range`, invalid triplets are skipped.
    pub fn ranges<C: Control>(
        &self,
        io: &mut C,
        clock: ResolvedClock,
    ) -> Result<Vec<RateRange>, Error> {
        let head = get(io, self.control_interface, clock.source, 1, 0, 2, 2)?;
        let count = usize::from(u16::from_le_bytes(head.try_into().unwrap()));
        let length = u16::try_from(2 + count * 12)
            .map_err(|_| Error::Descriptor("clock frequency range count"))?;
        let bytes = get(io, self.control_interface, clock.source, 1, 0, 2, length)?;
        let mut ranges = Vec::new();
        for entry in bytes[2..].as_chunks::<12>().0 {
            let range = RateRange {
                min: u32::from_le_bytes(entry[..4].try_into().unwrap()),
                max: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                resolution: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
            };
            // Linux reads these as signed ints.
            if [range.min, range.max, range.resolution]
                .iter()
                .any(|v| *v > i32::MAX as u32)
                || range.max < range.min
            {
                continue;
            }
            ranges.push(range);
        }
        Ok(ranges)
    }
    /// The rates Linux announces for the source.
    pub fn rates<C: Control>(&self, io: &mut C, clock: ResolvedClock) -> Result<Rates, Error> {
        let mut table = Vec::new();
        for range in self.ranges(io, clock)? {
            if range.resolution == 1 {
                return Ok(Rates::Continuous {
                    min: range.min,
                    max: range.max,
                });
            }
            let mut rate = range.min;
            while rate <= range.max {
                table.push(rate);
                if table.len() >= MAX_RATES {
                    return Ok(Rates::Table(table));
                }
                if range.resolution == 0 {
                    break;
                }
                rate += range.resolution;
            }
        }
        Ok(Rates::Table(table))
    }
    /// Linux `get_sample_rate_v2v3`: the current frequency, read whatever the
    /// control bits say; 0 when the read fails.
    pub fn current_rate<C: Control>(&self, io: &mut C, clock: ResolvedClock) -> u32 {
        get(io, self.control_interface, clock.source, 1, 0, 1, 4)
            .map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    }
    /// Linux `set_sample_rate_v2v3`: write `rate` when the clock runs at
    /// another and the frequency is writable, then require a valid clock. A
    /// failed write fails; a read-only or different running frequency does
    /// not. Returns the rate the clock runs at, 0 when unknown.
    pub fn set_rate<C: Control>(
        &self,
        io: &mut C,
        clock: ResolvedClock,
        rate: u32,
    ) -> Result<u32, Error> {
        let previous = self.current_rate(io, clock);
        let mut running = previous;
        if previous != rate {
            let Entity::ClockSource { controls, .. } = self.entity(clock.source)? else {
                return Err(Error::ClockInvalid);
            };
            if access(u32::from(*controls), 1)?.1 {
                set(
                    io,
                    self.control_interface,
                    clock.source,
                    1,
                    0,
                    &rate.to_le_bytes(),
                )?;
                running = match self.current_rate(io, clock) {
                    0 => previous,
                    current => current,
                };
            }
        }
        self.valid_clock(io, clock)?;
        Ok(running)
    }
    /// The post-change validation of `set_sample_rate_v2v3`.
    pub fn valid_clock<C: Control>(&self, io: &mut C, clock: ResolvedClock) -> Result<(), Error> {
        if self.source_valid(io, clock.terminal, clock.source) {
            Ok(())
        } else {
            Err(Error::ClockInvalid)
        }
    }
    pub(super) fn feature(
        &self,
        id: u8,
        channel: u8,
        selector: u8,
        write: bool,
    ) -> Result<(), Error> {
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
        signed_current(io, self.protocol, self.control_interface, id, 2, channel)
    }
    pub fn set_volume<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        value: i16,
    ) -> Result<(), Error> {
        self.feature(id, channel, 2, true)?;
        set_signed_control(
            io,
            self.protocol,
            self.control_interface,
            id,
            2,
            channel,
            value,
        )
    }
}

pub(super) fn signed_current<C: Control>(
    io: &mut C,
    protocol: u8,
    interface: u8,
    id: u8,
    selector: u8,
    channel: u8,
) -> Result<i16, Error> {
    let request = if protocol == super::UAC1 { 0x81 } else { 1 };
    Ok(i16::from_le_bytes(
        get(io, interface, id, selector, channel, request, 2)?
            .try_into()
            .unwrap(),
    ))
}

pub(super) fn set_signed_control<C: Control>(
    io: &mut C,
    protocol: u8,
    interface: u8,
    id: u8,
    selector: u8,
    channel: u8,
    value: i16,
) -> Result<(), Error> {
    let ranges = if protocol == super::UAC1 {
        let mut values = Vec::new();
        for request in [0x82, 0x83, 0x84] {
            // UAC1 GET_MIN, GET_MAX, GET_RES
            values.extend_from_slice(&get(io, interface, id, selector, channel, request, 2)?);
        }
        values
    } else {
        let head = get(io, interface, id, selector, channel, 2, 2)?;
        let count = usize::from(u16::from_le_bytes(head.try_into().unwrap()));
        if !(1..=64).contains(&count) {
            return Err(Error::Descriptor("volume range count"));
        }
        let ranges = get(
            io,
            interface,
            id,
            selector,
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
    set(io, interface, id, selector, channel, &value.to_le_bytes())?;
    if signed_current(io, protocol, interface, id, selector, channel)? != value {
        return Err(Error::ControlReadback);
    }
    Ok(())
}
