// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 Intel Corporation
// Copyright (c) 2026 Stela contributors
use super::{Community, Error, Group, Profile, RegisterIo};
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

const MAX_PADS: usize = 512;
const RX: u32 = 1 << 1;
const TX: u32 = 1;
const TX_DISABLE: u32 = 1 << 8;
const RX_DISABLE: u32 = 1 << 9;
const MODE: u32 = 15 << 10;
const ROUTES: u32 = 15 << 17;
const INVERT: u32 = 1 << 23;
const FILTER: u32 = 1 << 24;
const EVENT: u32 = 3 << 25;
const TERM: u32 = 7 << 10;
const TERM_UP: u32 = 1 << 13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Input,
    Output,
    Bidirectional,
    HighImpedance,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interrupt {
    Disabled,
    Rising,
    Falling,
    BothEdges,
    High,
    Low,
}
impl Interrupt {
    fn bits(self) -> u32 {
        match self {
            Self::Disabled => 2 << 25,
            Self::Rising => 1 << 25,
            Self::Falling => (1 << 25) | INVERT,
            Self::BothEdges => 3 << 25,
            Self::High => 0,
            Self::Low => INVERT,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pull {
    Disabled,
    Up(u32),
    Down(u32),
}

/// Captured hardware effects survive a later failed consumer/access. A bit in
/// `acknowledged` is an actual posted W1C, not an assertion that the peripheral
/// consumed its cause. `delivered` requires the consumer to return success.
#[derive(Debug)]
#[must_use]
pub struct ServiceReport {
    /// Publication was attempted; a failed write/flush may already have consumed
    /// this cause. Retain this evidence even when confirmation is unavailable.
    pub acknowledgement_attempted: [u64; 8],
    pub acknowledged: [u64; 8],
    pub delivered: [u64; 8],
    pub storm_masked: [u64; 8],
    pub error: Option<Error>,
}
fn mark(bits: &mut [u64; 8], pin: u16) {
    bits[usize::from(pin) / 64] |= 1 << (pin % 64);
}

#[derive(Clone, Copy)]
struct LiveCommunity {
    descriptor: Community,
    pad_base: usize,
    revision: u16,
}
impl LiveCommunity {
    fn stride(self) -> usize {
        if self.revision >= 0x92 { 16 } else { 8 }
    }
    fn cfg(self, pin: u16, register: usize) -> usize {
        self.pad_base + usize::from(pin - self.descriptor.first) * self.stride() + register
    }
}
#[derive(Clone, Copy)]
struct Saved {
    pin: u16,
    words: [u32; 3],
}

/// Serialized process/deferred protocol owner. No public constructor exists:
/// native ACPI resource, pad/firmware exclusion and parent-line ownership are
/// still required before an actual platform may expose attachment.
pub struct Controller<R: RegisterIo> {
    registers: ManuallyDrop<R>,
    profile: &'static Profile,
    communities: Vec<LiveCommunity>,
    saved: Vec<Saved>,
    fault: bool,
    restored: bool,
    retired: bool,
}
impl<R: RegisterIo> Controller<R> {
    #[allow(dead_code)] // Private protocol admission, never a native pad grant.
    pub(in crate::bus::gpio) fn new(
        registers: R,
        profile: &'static Profile,
        pins: &[u16],
    ) -> Result<Self, Error> {
        let mut this = Self {
            registers: ManuallyDrop::new(registers),
            profile,
            communities: Vec::new(),
            saved: Vec::new(),
            fault: false,
            restored: false,
            retired: false,
        };
        this.communities
            .try_reserve_exact(profile.communities.len())
            .map_err(|_| Error::Allocation)?;
        this.saved
            .try_reserve_exact(pins.len())
            .map_err(|_| Error::Allocation)?;
        for descriptor in profile.communities {
            let bar = descriptor.bar;
            let bytes = this.registers.bytes(bar)?;
            let revision_word = this.read(bar, 0)?;
            if revision_word == u32::MAX {
                return Err(Error::Access);
            }
            let revision = (revision_word >> 16) as u16;
            let mut offset: usize = 4;
            let mut visited = [0usize; 64];
            let mut count = 0;
            loop {
                if offset & 3 != 0
                    || offset.checked_add(4).is_none_or(|end| end > bytes)
                    || count == visited.len()
                    || visited[..count].contains(&offset)
                {
                    return Err(Error::InvalidProfile);
                }
                visited[count] = offset;
                count += 1;
                let capability = this.read(bar, offset)?;
                offset = (capability & 0xffff) as usize;
                if offset == 0 {
                    break;
                }
            }
            let pad_base = this.read(bar, 12)? as usize;
            let live = LiveCommunity {
                descriptor: *descriptor,
                pad_base,
                revision,
            };
            let pad_end = pad_base
                .checked_add(usize::from(descriptor.count) * live.stride())
                .ok_or(Error::InvalidProfile)?;
            if pad_base & 3 != 0
                || pad_base < 16
                || pad_end > bytes
                || usize::from(descriptor.first) + usize::from(descriptor.count) > MAX_PADS
            {
                return Err(Error::InvalidProfile);
            }
            for group in descriptor.groups {
                if group.count == 0
                    || group.count > 32
                    || group.first < descriptor.first
                    || u32::from(group.first) + u32::from(group.count)
                        > u32::from(descriptor.first) + u32::from(descriptor.count)
                {
                    return Err(Error::InvalidProfile);
                }
                let own_end = if revision >= 0x110 {
                    descriptor.pad_own + usize::from(descriptor.count) * 4
                } else {
                    descriptor.pad_own + usize::from(group.pad_own + group.count.div_ceil(8)) * 4
                };
                let ends = [
                    own_end,
                    descriptor.lock + usize::from(group.register) * 8 + 8,
                    descriptor.host_own + usize::from(group.register) * 4 + 4,
                    descriptor.status + usize::from(group.register) * 4 + 4,
                    descriptor.enable + usize::from(group.register) * 4 + 4,
                ];
                if ends.into_iter().any(|end| end > pad_base) {
                    return Err(Error::InvalidProfile);
                }
            }
            this.communities.push(live);
        }
        for &pin in pins {
            if this.saved.iter().any(|saved| saved.pin == pin) {
                return Err(Error::InvalidPad);
            }
            let snapshot = this.snapshot(pin)?;
            this.saved.push(snapshot);
        }
        Ok(this)
    }
    pub fn profile(&self) -> &'static Profile {
        self.profile
    }
    pub fn faulted(&self) -> bool {
        self.fault
    }
    pub fn retired(&self) -> bool {
        self.retired
    }
}
#[cfg(any(feature = "native-acpi", test))]
impl<R: RegisterIo> Controller<R> {
    pub(in crate::bus::gpio) fn has_claims(&self) -> bool {
        !self.saved.is_empty()
    }
    pub(in crate::bus::gpio) fn is_claimed(&self, pin: u16) -> bool {
        self.saved.iter().any(|saved| saved.pin == pin)
    }
    /// The native supplier's actual broker admits a line before this snapshot.
    /// Reserve storage before any later request can change hardware.
    pub(in crate::bus::gpio) fn capture(&mut self, pin: u16) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.fault {
            return Err(Error::Faulted);
        }
        if self.is_claimed(pin) {
            return Err(Error::InvalidPad);
        }
        self.saved.try_reserve(1).map_err(|_| Error::Allocation)?;
        let snapshot = self.snapshot(pin)?;
        self.saved.push(snapshot);
        Ok(())
    }
    pub(in crate::bus::gpio) fn claim_debounce(
        &mut self,
        pin: u16,
        micros: u32,
    ) -> Result<(), Error> {
        let (community, _) = self.check(pin)?;
        if micros == 0
            && self.read(community.descriptor.bar, community.cfg(pin, 0))? & FILTER == 0
            && (community.revision < 0x92
                || self.read(community.descriptor.bar, community.cfg(pin, 8))? & 31 == 0)
        {
            return Ok(());
        }
        self.debounce(pin, micros)
    }
    /// Raw latch writes preserve the actual ACPI Preserve direction.
    pub(in crate::bus::gpio) fn write_latch(&mut self, pin: u16, high: bool) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, false, true)?;
        if self.read(community.descriptor.bar, community.cfg(pin, 0))? & MODE != 0 {
            return Err(Error::Direction);
        }
        self.update(community, pin, 0, TX, if high { TX } else { 0 })
    }
    /// The supplier stops/drains this line's children first. Failed restoration
    /// keeps the exact snapshot, mapping and claim available for retirement.
    pub(in crate::bus::gpio) fn release_pad(&mut self, pin: u16) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        let index = self
            .saved
            .iter()
            .position(|saved| saved.pin == pin)
            .ok_or(Error::UnownedPad)?;
        let saved = self.saved[index];
        let (community, group) = self.locate(pin)?;
        self.host_owner(community, group, pin)?;
        self.mask(community, group, pin, true)?;
        let current = [
            self.read(community.descriptor.bar, community.cfg(pin, 0))? & !RX,
            self.read(community.descriptor.bar, community.cfg(pin, 4))?,
            if community.revision >= 0x92 {
                self.read(community.descriptor.bar, community.cfg(pin, 8))?
            } else {
                0
            },
        ];
        if current != saved.words {
            self.unlocked(community, group, pin, true, true)?;
            self.update(
                community,
                pin,
                0,
                TX_DISABLE | RX_DISABLE,
                TX_DISABLE | RX_DISABLE,
            )?;
            self.update(community, pin, 4, u32::MAX, saved.words[1])?;
            if community.revision >= 0x92 {
                self.update(community, pin, 8, u32::MAX, saved.words[2])?;
            }
            self.update(community, pin, 0, !RX, saved.words[0])?;
        }
        self.saved.remove(index);
        Ok(())
    }
}
impl<R: RegisterIo> Controller<R> {
    fn snapshot(&mut self, pin: u16) -> Result<Saved, Error> {
        let (community, group) = self.locate(pin)?;
        self.host_owner(community, group, pin)?;
        let value = self.read(community.descriptor.bar, community.cfg(pin, 0))?;
        let enabled = self.read(
            community.descriptor.bar,
            community.descriptor.enable + usize::from(group.register) * 4,
        )?;
        if value & ROUTES != 0 || enabled & (1 << (pin - group.first)) != 0 {
            return Err(Error::FirmwareInterrupt);
        }
        let mut words = [
            value & !RX,
            self.read(community.descriptor.bar, community.cfg(pin, 4))?,
            0,
        ];
        if community.revision >= 0x92 {
            words[2] = self.read(community.descriptor.bar, community.cfg(pin, 8))?;
        }
        Ok(Saved { pin, words })
    }
    fn locate(&self, pin: u16) -> Result<(LiveCommunity, Group), Error> {
        self.communities
            .iter()
            .find_map(|community| {
                community
                    .descriptor
                    .groups
                    .iter()
                    .find(|group| {
                        pin >= group.first && pin - group.first < group.count && group.gpio >= 0
                    })
                    .map(|group| (*community, *group))
            })
            .ok_or(Error::InvalidPad)
    }
    fn check(&self, pin: u16) -> Result<(LiveCommunity, Group), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.fault {
            return Err(Error::Faulted);
        }
        if !self.saved.iter().any(|saved| saved.pin == pin) {
            return Err(Error::UnownedPad);
        }
        self.locate(pin)
    }
    fn read(&mut self, bar: u8, offset: usize) -> Result<u32, Error> {
        let result = self.registers.read32(bar, offset);
        if result.is_err() {
            self.fault = true;
        }
        result
    }
    fn write(&mut self, bar: u8, offset: usize, value: u32) -> Result<(), Error> {
        let result = self.registers.write32(bar, offset, value);
        if result.is_err() {
            self.fault = true;
        }
        result
    }
    fn host_owner(
        &mut self,
        community: LiveCommunity,
        group: Group,
        pin: u16,
    ) -> Result<(), Error> {
        let descriptor = community.descriptor;
        if descriptor.pad_own != 0 {
            let (offset, mask) = if community.revision >= 0x110 {
                (
                    descriptor.pad_own + usize::from(pin - descriptor.first) * 4,
                    7,
                )
            } else {
                let local = pin - group.first;
                (
                    descriptor.pad_own + usize::from(group.pad_own + local / 8) * 4,
                    15 << (local % 8 * 4),
                )
            };
            if self.read(descriptor.bar, offset)? & mask != 0 {
                return Err(Error::FirmwareOwner);
            }
        }
        Ok(())
    }
    fn unlocked(
        &mut self,
        community: LiveCommunity,
        group: Group,
        pin: u16,
        config: bool,
        tx: bool,
    ) -> Result<(), Error> {
        self.host_owner(community, group, pin)?;
        let descriptor = community.descriptor;
        if descriptor.lock != 0 {
            let offset = descriptor.lock + usize::from(group.register) * 8;
            let mask = 1 << (pin - group.first);
            if config && self.read(descriptor.bar, offset)? & mask != 0 {
                return Err(Error::Locked);
            }
            if tx && self.read(descriptor.bar, offset + 4)? & mask != 0 {
                return Err(Error::TxLocked);
            }
        }
        Ok(())
    }
    fn update(
        &mut self,
        community: LiveCommunity,
        pin: u16,
        word: usize,
        mask: u32,
        bits: u32,
    ) -> Result<(), Error> {
        let bar = community.descriptor.bar;
        let offset = community.cfg(pin, word);
        let old = self.read(bar, offset)?;
        let wanted = (old & !mask) | bits;
        self.write(bar, offset, wanted)?;
        let observed = self.read(bar, offset)?;
        let stable = if word == 0 { !RX } else { u32::MAX };
        if observed & stable != wanted & stable {
            self.fault = true;
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub fn value(&mut self, pin: u16) -> Result<bool, Error> {
        let (community, group) = self.check(pin)?;
        self.host_owner(community, group, pin)?;
        let value = self.read(community.descriptor.bar, community.cfg(pin, 0))?;
        if value & MODE != 0 {
            return Err(Error::Direction);
        }
        Ok(value & if value & TX_DISABLE == 0 { TX } else { RX } != 0)
    }
    pub fn direction(&mut self, pin: u16) -> Result<Direction, Error> {
        let (community, group) = self.check(pin)?;
        self.host_owner(community, group, pin)?;
        let value = self.read(community.descriptor.bar, community.cfg(pin, 0))?;
        if value & MODE != 0 {
            return Err(Error::Direction);
        }
        Ok(match value & (TX_DISABLE | RX_DISABLE) {
            TX_DISABLE => Direction::Input,
            RX_DISABLE => Direction::Output,
            0 => Direction::Bidirectional,
            _ => Direction::HighImpedance,
        })
    }
    /// Original request policy avoids glitches when firmware already selected
    /// GPIO mode. A real native producer must separately authorize mux takeover.
    pub fn request_gpio(&mut self, pin: u16) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.host_owner(community, group, pin)?;
        if self.read(community.descriptor.bar, community.cfg(pin, 0))? & MODE == 0 {
            return Ok(());
        }
        self.unlocked(community, group, pin, true, false)?;
        self.update(
            community,
            pin,
            0,
            MODE | ROUTES | TX_DISABLE | RX_DISABLE,
            TX_DISABLE,
        )
    }
    pub fn direction_input(&mut self, pin: u16) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, true, false)?;
        self.require_gpio_masked(community, group, pin)?;
        self.update(community, pin, 0, RX_DISABLE | TX_DISABLE, TX_DISABLE)
    }
    pub fn direction_output(&mut self, pin: u16, high: bool) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, true, true)?;
        self.require_gpio_masked(community, group, pin)?;
        // Source programs the output latch before enabling the output buffer.
        self.update(community, pin, 0, TX, if high { TX } else { 0 })?;
        self.update(community, pin, 0, RX_DISABLE | TX_DISABLE, RX_DISABLE)
    }
    pub fn set_output(&mut self, pin: u16, high: bool) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, false, true)?;
        let value = self.read(community.descriptor.bar, community.cfg(pin, 0))?;
        if value & (MODE | TX_DISABLE) != 0 {
            return Err(Error::Direction);
        }
        self.update(community, pin, 0, TX, if high { TX } else { 0 })
    }
    fn require_gpio_masked(
        &mut self,
        community: LiveCommunity,
        group: Group,
        pin: u16,
    ) -> Result<(), Error> {
        let descriptor = community.descriptor;
        if self.read(descriptor.bar, community.cfg(pin, 0))? & MODE != 0 {
            return Err(Error::Direction);
        }
        if self.read(
            descriptor.bar,
            descriptor.enable + usize::from(group.register) * 4,
        )? & (1 << (pin - group.first))
            != 0
        {
            return Err(Error::InterruptActive);
        }
        Ok(())
    }
    pub fn pull(&mut self, pin: u16, pull: Pull) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        let (strength, up) = match pull {
            Pull::Disabled => (0, false),
            Pull::Up(ohms) => (ohms, true),
            Pull::Down(ohms) => (ohms, false),
        };
        let term = match strength {
            0 if pull == Pull::Disabled => 0,
            20_000 => 4,
            1 | 5_000 => 2,
            4_000 => 6,
            1_000 if up || community.revision >= 0x92 => 1,
            833 if up || community.revision >= 0x92 => 3,
            _ => return Err(Error::InvalidPull),
        };
        self.unlocked(community, group, pin, true, false)?;
        self.update(
            community,
            pin,
            4,
            TERM | TERM_UP,
            (term << 10) | if up { TERM_UP } else { 0 },
        )
    }
    pub fn high_impedance(&mut self, pin: u16) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, true, false)?;
        self.require_gpio_masked(community, group, pin)?;
        self.update(
            community,
            pin,
            0,
            RX_DISABLE | TX_DISABLE,
            RX_DISABLE | TX_DISABLE,
        )
    }
    pub fn debounce(&mut self, pin: u16, micros: u32) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        let units = u64::from(micros) * 1_000 / 31_250;
        let exponent = if micros == 0 {
            0
        } else {
            64 - units.saturating_sub(1).leading_zeros()
        };
        if micros != 0 && !(3..=15).contains(&exponent) {
            return Err(Error::InvalidDebounce);
        }
        if community.revision < 0x92 {
            return Err(Error::Unsupported);
        }
        self.unlocked(community, group, pin, true, false)?;
        self.update(
            community,
            pin,
            0,
            FILTER,
            if micros == 0 { 0 } else { FILTER },
        )?;
        self.update(
            community,
            pin,
            8,
            31,
            exponent << 1 | u32::from(micros != 0),
        )
    }
    pub fn interrupt_type(&mut self, pin: u16, kind: Interrupt) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.unlocked(community, group, pin, true, false)?;
        let descriptor = community.descriptor;
        if descriptor.host_own != 0
            && self.read(
                descriptor.bar,
                descriptor.host_own + usize::from(group.register) * 4,
            )? & (1 << (pin - group.first))
                == 0
        {
            return Err(Error::AcpiInterrupt);
        }
        if self.read(
            descriptor.bar,
            descriptor.enable + usize::from(group.register) * 4,
        )? & (1 << (pin - group.first))
            != 0
        {
            return Err(Error::InterruptActive);
        }
        self.update(
            community,
            pin,
            0,
            MODE | ROUTES | RX_DISABLE | TX_DISABLE,
            TX_DISABLE,
        )?;
        self.update(community, pin, 0, EVENT | INVERT, kind.bits())
    }
    fn mask(
        &mut self,
        community: LiveCommunity,
        group: Group,
        pin: u16,
        masked: bool,
    ) -> Result<(), Error> {
        let descriptor = community.descriptor;
        let offset = descriptor.enable + usize::from(group.register) * 4;
        let bit = 1 << (pin - group.first);
        let old = self.read(descriptor.bar, offset)?;
        let wanted = if masked { old & !bit } else { old | bit };
        self.write(descriptor.bar, offset, wanted)?;
        if self.read(descriptor.bar, offset)? != wanted {
            self.fault = true;
            return Err(Error::Readback);
        }
        Ok(())
    }
    fn ack(&mut self, community: LiveCommunity, group: Group, pin: u16) -> Result<(), Error> {
        let descriptor = community.descriptor;
        let offset = descriptor.status + usize::from(group.register) * 4;
        self.write(descriptor.bar, offset, 1 << (pin - group.first))?;
        // A fresh cause may already be pending; this is a flush, not a false
        // requirement that a live level/edge source remain deasserted.
        let _ = self.read(descriptor.bar, offset)?;
        Ok(())
    }
    /// Original mask/unmask first acknowledges this one stale status bit.
    pub fn interrupt_mask(&mut self, pin: u16, masked: bool) -> Result<(), Error> {
        let (community, group) = self.check(pin)?;
        self.host_owner(community, group, pin)?;
        if !masked {
            if community.descriptor.host_own != 0
                && self.read(
                    community.descriptor.bar,
                    community.descriptor.host_own + usize::from(group.register) * 4,
                )? & (1 << (pin - group.first))
                    == 0
            {
                return Err(Error::AcpiInterrupt);
            }
            let value = self.read(community.descriptor.bar, community.cfg(pin, 0))?;
            if value & (MODE | RX_DISABLE | ROUTES) != 0
                || value & TX_DISABLE == 0
                || value & EVENT == 2 << 25
            {
                return Err(Error::Direction);
            }
        }
        self.ack(community, group, pin)?;
        self.mask(community, group, pin, masked)
    }
    /// One finite source snapshot per group. Actual edge ACK precedes the
    /// consumer, preserving a second edge arriving during its execution. Level
    /// delivery additionally masks through the callback and reports reassertion.
    pub fn service(&mut self, mut consumer: impl FnMut(u16) -> Result<(), Error>) -> ServiceReport {
        let mut report = ServiceReport {
            acknowledgement_attempted: [0; 8],
            acknowledged: [0; 8],
            delivered: [0; 8],
            storm_masked: [0; 8],
            error: None,
        };
        if self.retired {
            report.error = Some(Error::Retired);
            return report;
        }
        if self.fault {
            report.error = Some(Error::Faulted);
            return report;
        }
        let result = self.service_inner(&mut consumer, &mut report);
        if let Err(error) = result {
            self.fault = true;
            report.error = Some(error);
        }
        report
    }
    fn service_inner(
        &mut self,
        consumer: &mut impl FnMut(u16) -> Result<(), Error>,
        report: &mut ServiceReport,
    ) -> Result<(), Error> {
        for index in 0..self.communities.len() {
            let community = self.communities[index];
            let descriptor = community.descriptor;
            for group in descriptor.groups {
                let pending = self.read(
                    descriptor.bar,
                    descriptor.status + usize::from(group.register) * 4,
                )? & self.read(
                    descriptor.bar,
                    descriptor.enable + usize::from(group.register) * 4,
                )?;
                for local in 0..group.count {
                    let pin = group.first + local;
                    if pending & (1 << local) == 0
                        || !self.saved.iter().any(|saved| saved.pin == pin)
                    {
                        continue;
                    }
                    self.host_owner(community, *group, pin)?;
                    if descriptor.host_own != 0
                        && self.read(
                            descriptor.bar,
                            descriptor.host_own + usize::from(group.register) * 4,
                        )? & (1 << local)
                            == 0
                    {
                        return Err(Error::AcpiInterrupt);
                    }
                    let value = self.read(descriptor.bar, community.cfg(pin, 0))?;
                    if value & (MODE | ROUTES | RX_DISABLE) != 0 || value & TX_DISABLE == 0 {
                        return Err(Error::Direction);
                    }
                    let level = value & EVENT == 0;
                    if level {
                        self.mask(community, *group, pin, true)?;
                    }
                    mark(&mut report.acknowledgement_attempted, pin);
                    self.ack(community, *group, pin)?;
                    mark(&mut report.acknowledged, pin);
                    if consumer(pin).is_err() {
                        self.mask(community, *group, pin, true)?;
                        return Err(Error::Consumer);
                    }
                    mark(&mut report.delivered, pin);
                    if level {
                        if self.read(
                            descriptor.bar,
                            descriptor.status + usize::from(group.register) * 4,
                        )? & (1 << local)
                            != 0
                        {
                            mark(&mut report.storm_masked, pin);
                        } else {
                            self.mask(community, *group, pin, false)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.retired {
            return Ok(());
        }
        self.fault = true;
        if !self.restored {
            // Quiesce every owned source before restoring any pad's controls.
            for index in 0..self.saved.len() {
                let pin = self.saved[index].pin;
                let (community, group) = self.locate(pin)?;
                self.host_owner(community, group, pin)?;
                self.mask(community, group, pin, true)?;
            }
            for index in 0..self.saved.len() {
                let saved = self.saved[index];
                let (community, group) = self.locate(saved.pin)?;
                let current = [
                    self.read(community.descriptor.bar, community.cfg(saved.pin, 0))? & !RX,
                    self.read(community.descriptor.bar, community.cfg(saved.pin, 4))?,
                    if community.revision >= 0x92 {
                        self.read(community.descriptor.bar, community.cfg(saved.pin, 8))?
                    } else {
                        0
                    },
                ];
                // Read-only use of a locked GPIO need not change it to restore
                // identical controls. No lock is bypassed for a real change.
                if current == saved.words {
                    continue;
                }
                self.unlocked(community, group, saved.pin, true, true)?;
                self.update(
                    community,
                    saved.pin,
                    0,
                    TX_DISABLE | RX_DISABLE,
                    TX_DISABLE | RX_DISABLE,
                )?;
                self.update(community, saved.pin, 4, u32::MAX, saved.words[1])?;
                if community.revision >= 0x92 {
                    self.update(community, saved.pin, 8, u32::MAX, saved.words[2])?;
                }
                self.update(community, saved.pin, 0, !RX, saved.words[0])?;
            }
            self.restored = true;
        }
        self.registers.finish()?;
        self.retired = true;
        Ok(())
    }
}
impl<R: RegisterIo> Drop for Controller<R> {
    fn drop(&mut self) {
        if self.retired {
            // SAFETY: private owned transport fully retired after acknowledged
            // restoration; no parent registration or native callback exists.
            unsafe { ManuallyDrop::drop(&mut self.registers) };
        }
    }
}
