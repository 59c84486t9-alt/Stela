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
    request(io, interface, entity, selector, channel, 1, bytes)
}
fn request<C: Control>(
    io: &mut C,
    interface: u8,
    entity: u8,
    selector: u8,
    channel: u8,
    request: u8,
    bytes: &[u8],
) -> Result<(), Error> {
    let reply = io.control(
        setup(
            0x21,
            request,
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
        // mixer_ctl_selector_put writes with no readback.
        let selector = if self.protocol == super::UAC1 { 0 } else { 1 };
        set(io, self.control_interface, id, selector, 0, &[pin])
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
    /// A boolean control reads as `!!val`, as `get_relative_value` has it.
    pub fn mute<C: Control>(&self, io: &mut C, id: u8, channel: u8) -> Result<bool, Error> {
        self.feature(id, channel, 1, false)?;
        let request = if self.protocol == super::UAC1 {
            0x81
        } else {
            1
        };
        Ok(get(io, self.control_interface, id, 1, channel, request, 1)?[0] != 0)
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
        )
    }
    pub fn volume<C: Control>(&self, io: &mut C, id: u8, channel: u8) -> Result<i16, Error> {
        self.feature(id, channel, 2, false)?;
        signed_current(io, self.protocol, self.control_interface, id, 2, channel)
    }
    /// Probe a volume's range once, before its first set; probing writes.
    pub fn volume_range<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
    ) -> Result<MixerRange, Error> {
        self.feature(id, channel, 2, false)?;
        probe_range(
            io,
            self.protocol,
            self.control_interface,
            id,
            2,
            channel,
            Width::S16,
        )
    }
    pub fn set_volume<C: Control>(
        &self,
        io: &mut C,
        id: u8,
        channel: u8,
        range: MixerRange,
        value: i16,
    ) -> Result<(), Error> {
        self.feature(id, channel, 2, true)?;
        let value = range.snap(i64::from(value)) as i16;
        set_signed(io, self.control_interface, id, 2, channel, value)
    }
}

/// A numeric control's range as Linux `get_min_max_with_quirks` settles it,
/// in device units (1/256 dB for volumes, gains and mixer cells).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixerRange {
    pub min: i64,
    pub max: i64,
    pub res: i64,
    /// dB bounds in 1/100 dB, as ALSA TLV reports them; `None` when the
    /// range is bogus, its maximum at or below -96 dB.
    pub db: Option<(i64, i64)>,
}
impl MixerRange {
    /// `get_relative_value` then `get_abs_value`: the step at or below
    /// `value`, clamped to the range.
    pub fn snap(self, value: i64) -> i64 {
        let step = if value < self.min {
            0
        } else if value >= self.max {
            (self.max - self.min + self.res - 1) / self.res
        } else {
            (value - self.min) / self.res
        };
        if step < 0 {
            return self.min;
        }
        (self.min + step * self.res).min(self.max)
    }
}

/// How a numeric control's value is carried: its width in bytes and
/// whether `convert_signed_value` sign-extends it.
#[derive(Clone, Copy)]
pub(super) struct Width {
    pub bytes: u16,
    pub signed: bool,
}
impl Width {
    pub(super) const S16: Self = Self {
        bytes: 2,
        signed: true,
    };
    pub(super) fn decode(self, bytes: &[u8]) -> i64 {
        let mut raw = [0; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let value = u64::from_le_bytes(raw);
        let shift = 64 - 8 * u32::from(self.bytes);
        if self.signed {
            ((value << shift) as i64) >> shift
        } else {
            value as i64
        }
    }
    pub(super) fn encode(self, value: i64) -> Vec<u8> {
        value.to_le_bytes()[..usize::from(self.bytes)].to_vec()
    }
}

/// Linux `get_min_max_with_quirks`. MIN and MAX must read; a RES that does
/// not reads as 1, and UAC1 asks SET_RES for halving it while the device
/// accepts. Then, when the range is not one value, a control whose GET_CUR
/// never follows SET_CUR at either end is sticky and refused after being
/// left at its maximum; otherwise RES doubles until a step past the current
/// value reads back, and the current value is restored. UAC2 and UAC3 use
/// the first RANGE triplet.
#[allow(clippy::too_many_arguments)]
pub(super) fn probe_range<C: Control>(
    io: &mut C,
    protocol: u8,
    interface: u8,
    id: u8,
    selector: u8,
    channel: u8,
    width: Width,
) -> Result<MixerRange, Error> {
    let n = width.bytes;
    let value = |io: &mut C, request: u8| -> Result<i64, Error> {
        if protocol == super::UAC1 {
            let bytes = get(io, interface, id, selector, channel, request, n)?;
            return Ok(width.decode(&bytes));
        }
        let range = get(io, interface, id, selector, channel, 2, 2 + 3 * n)?;
        let at = 2 + usize::from(n) * usize::from(request - 0x82);
        Ok(width.decode(&range[at..at + usize::from(n)]))
    };
    // UAC_GET_MAX before UAC_GET_MIN, then UAC_GET_RES.
    let max = value(io, 0x83)?;
    let min = value(io, 0x82)?;
    let mut res = match value(io, 0x84) {
        Ok(res) if protocol == super::UAC1 => {
            let last_valid = res;
            let mut res = res;
            while res > 1 {
                let half = width.encode(res / 2);
                if request(io, interface, id, selector, channel, 4, &half).is_err() {
                    break;
                }
                res /= 2;
            }
            value(io, 0x84).unwrap_or(last_valid)
        }
        Ok(res) => res,
        Err(_) => 1,
    };
    if res == 0 {
        res = 1;
    }
    let current = |io: &mut C| -> Result<i64, Error> {
        let request = if protocol == super::UAC1 { 0x81 } else { 1 };
        Ok(width.decode(&get(io, interface, id, selector, channel, request, n)?))
    };
    let set = |io: &mut C, value: i64| {
        self::set(io, interface, id, selector, channel, &width.encode(value))
    };
    if min < max
        && let Ok(saved) = current(io)
    {
        // check_sticky_volume_control: assume non-sticky on failure.
        let sticky = [min, max]
            .into_iter()
            .filter(|&test| test != saved)
            .all(|test| set(io, test).is_ok() && current(io).is_ok_and(|check| check == saved));
        if sticky {
            let _ = set(io, max);
            return Err(Error::Unsupported("sticky mixer values"));
        }
        // check_volume_control_res
        if min + res < max {
            let last_valid = res;
            loop {
                let test = if saved < max {
                    saved + res
                } else {
                    saved - res
                };
                let check = if test < min || test > max || set(io, test).is_err() {
                    None
                } else {
                    current(io).ok()
                };
                match check {
                    None => {
                        res = last_valid;
                        break;
                    }
                    Some(check) if check == test => break,
                    Some(_) => res *= 2,
                }
            }
        }
        let _ = set(io, saved);
    }
    let (mut db_min, mut db_max) = (min * 100 / 256, max * 100 / 256);
    let db = if db_min > db_max {
        // Something is wrong; assume it is either from or to 0 dB.
        if db_min < 0 {
            db_max = 0;
        } else if db_min > 0 {
            db_min = 0;
        }
        if db_min > db_max {
            return Err(Error::Descriptor("mixer dB range"));
        }
        Some((db_min, db_max))
    } else if db_max <= -9600 {
        None
    } else {
        Some((db_min, db_max))
    };
    Ok(MixerRange { min, max, res, db })
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

/// SET_CUR without a readback, as `snd_usb_set_cur_mix_value` sends it.
pub(super) fn set_signed<C: Control>(
    io: &mut C,
    interface: u8,
    id: u8,
    selector: u8,
    channel: u8,
    value: i16,
) -> Result<(), Error> {
    set(io, interface, id, selector, channel, &value.to_le_bytes())
}
