// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014,2015 Ken Xue <Ken.Xue@amd.com>, Jeff Wu <Jeff.Wu@amd.com>
// Copyright (c) 2026 Stela contributors
//! AMD GPIO pad programming and interrupt status over the controller's register window.
use super::{Error, Pad, Profile, RegisterIo};
use core::mem::ManuallyDrop;

const PADS: usize = 184;
const MASTER: usize = 0xfc;
const SUMMARY_LO: usize = 0x2f8;
const SUMMARY_HI: usize = 0x2fc;
const EOI: u32 = 1 << 29;
const INTERNAL_DEBOUNCE: u32 = 1 << 15;
const LEVEL: u32 = 1 << 8;
const POLARITY: u32 = 3 << 9;
const ENABLE: u32 = 1 << 11;
const UNMASK: u32 = 1 << 12;
const WAKE_POLICY: u32 = (7 << 13) | (1 << 27);
const INPUT: u32 = 1 << 16;
const PULL: u32 = 3 << 20;
const VALUE: u32 = 1 << 22;
const OUTPUT: u32 = 1 << 23;
const STATUS: u32 = 3 << 28;
const DEBOUNCE: u32 = 0xff;
const SETTLE_READS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pull {
    Disabled,
    Up,
    Down,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interrupt {
    Rising,
    Falling,
    BothEdges,
    High,
    Low,
}
impl Interrupt {
    fn bits(self) -> u32 {
        match self {
            Self::Rising => 0,
            Self::Falling => 1 << 9,
            Self::BothEdges => 2 << 9,
            Self::High => LEVEL,
            Self::Low => LEVEL | (1 << 9),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    pub interrupt: bool,
    pub wake: bool,
}

/// Partial acknowledgements remain observable if a later operation fails.
#[derive(Debug)]
#[must_use]
pub struct ServiceReport {
    pub delivered: [u64; 3],
    pub storm_masked: [u64; 3],
    pub error: Option<Error>,
}

fn contains(bits: &[u64; 3], pad: Pad) -> bool {
    bits[usize::from(pad.0) / 64] & (1 << (pad.0 % 64)) != 0
}
fn insert(bits: &mut [u64; 3], pad: Pad) {
    bits[usize::from(pad.0) / 64] |= 1 << (pad.0 % 64);
}

/// Owned register protocol with sticky failure containment. Dropping an
/// unfinished/uncertain controller keeps its original register transport;
/// only successful retirement permits final transport release. Native admission
/// belongs to the ACPI/resource adapter; raw constructors stay internal.
pub struct Controller<R: RegisterIo> {
    registers: ManuallyDrop<R>,
    profile: Profile,
    owned: [u64; 3],
    saved: [u32; PADS],
    saved_mux: [Option<u8>; PADS],
    fault: bool,
    retired: bool,
    restored: bool,
}
impl<R: RegisterIo> Controller<R> {
    // The bitmap is internal protocol inventory, never a native grant. The real
    // resource adapter starts empty and captures each claimed line.
    #[cfg(any(test, feature = "native-acpi"))]
    pub(in crate::bus::gpio) fn new(
        registers: R,
        profile: Profile,
        owned: [u64; 3],
    ) -> Result<Self, Error> {
        let mut this = Self {
            registers: ManuallyDrop::new(registers),
            profile,
            owned,
            saved: [0; PADS],
            saved_mux: [None; PADS],
            fault: false,
            retired: false,
            restored: false,
        };
        if this.registers.bytes() < 0x300 || owned[0] & (1 << 63) != 0 || owned[2] >> 56 != 0 {
            return Err(Error::InvalidPad);
        }
        // Read-only admission: no global IRQ/wake initialization steals pads
        // from firmware. On uncertain access keep the complete transport.
        for number in 0..PADS as u8 {
            let Ok(pad) = Pad::new(number) else { continue };
            if !contains(&owned, pad) {
                continue;
            }
            let value = this.read(pad)?;
            if value & WAKE_POLICY != 0 {
                return Err(Error::FirmwareWake);
            }
            if value & (ENABLE | UNMASK) != 0 {
                return Err(Error::FirmwareInterrupt);
            }
            this.saved[usize::from(number)] = value & !(STATUS | INPUT);
        }
        Ok(this)
    }
    pub fn profile(&self) -> Profile {
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
        self.owned != [0; 3]
    }
    pub(in crate::bus::gpio) fn is_claimed(&self, pad: Pad) -> bool {
        contains(&self.owned, pad)
    }
    pub(in crate::bus::gpio) fn capture(&mut self, pad: Pad) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.fault {
            return Err(Error::Faulted);
        }
        if self.is_claimed(pad) {
            return Err(Error::InvalidPad);
        }
        let value = self.read(pad)?;
        if value & WAKE_POLICY != 0 {
            return Err(Error::FirmwareWake);
        }
        if value & (ENABLE | UNMASK) != 0 {
            return Err(Error::FirmwareInterrupt);
        }
        self.saved[usize::from(pad.0)] = value & !(STATUS | INPUT);
        self.saved_mux[usize::from(pad.0)] = None;
        insert(&mut self.owned, pad);
        Ok(())
    }
    pub(in crate::bus::gpio) fn claim_debounce(
        &mut self,
        pad: Pad,
        micros: u32,
    ) -> Result<(), Error> {
        self.check(pad)?;
        if micros == 0 && self.read(pad)? & DEBOUNCE == 0 {
            return Ok(());
        }
        self.debounce(pad, micros)
    }
    pub(in crate::bus::gpio) fn write_latch(&mut self, pad: Pad, high: bool) -> Result<(), Error> {
        self.check(pad)?;
        self.update(pad, VALUE, if high { VALUE } else { 0 })
    }
    /// The supplier masks and drains this line's users before release.
    pub(in crate::bus::gpio) fn release_pad(&mut self, pad: Pad) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if !self.is_claimed(pad) {
            return Err(Error::UnownedPad);
        }
        self.update(pad, ENABLE | UNMASK, 0)?;
        self.update(pad, OUTPUT, 0)?;
        if let Some(mux) = self.saved_mux[usize::from(pad.0)] {
            self.access(|r| r.write_mux(pad.0, mux))?;
            if self.access(|r| r.read_mux(pad.0))? != mux {
                return Err(Error::Readback);
            }
        }
        let saved = self.saved[usize::from(pad.0)];
        self.write(pad, saved)?;
        if self.read(pad)? & !(STATUS | INPUT) != saved {
            return Err(Error::Readback);
        }
        self.owned[usize::from(pad.0) / 64] &= !(1 << (pad.0 % 64));
        self.saved_mux[usize::from(pad.0)] = None;
        Ok(())
    }
}
impl<R: RegisterIo> Controller<R> {
    fn check(&self, pad: Pad) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.fault {
            return Err(Error::Faulted);
        }
        if !contains(&self.owned, pad) {
            return Err(Error::UnownedPad);
        }
        Ok(())
    }
    fn access<T>(
        &mut self,
        operation: impl FnOnce(&mut R) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let result = operation(&mut self.registers);
        if result.is_err() {
            self.fault = true;
        }
        result
    }
    fn read(&mut self, pad: Pad) -> Result<u32, Error> {
        self.access(|r| r.read32(usize::from(pad.0) * 4))
    }
    fn write(&mut self, pad: Pad, value: u32) -> Result<(), Error> {
        self.access(|r| r.write32(usize::from(pad.0) * 4, value))
    }
    fn update(&mut self, pad: Pad, mask: u32, value: u32) -> Result<(), Error> {
        let before = self.read(pad)?;
        let wanted = (before & !(mask | STATUS)) | value;
        self.write(pad, wanted)?;
        let after = self.read(pad)?;
        // Compare all stable controls, not just requested bits. Never infer
        // an acknowledgement from the local shadow or a successful write.
        if after & !(INPUT | STATUS) != wanted & !(INPUT | STATUS) {
            self.fault = true;
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub fn input(&mut self, pad: Pad) -> Result<bool, Error> {
        self.check(pad)?;
        Ok(self.read(pad)? & INPUT != 0)
    }
    pub fn direction_input(&mut self, pad: Pad) -> Result<(), Error> {
        self.check(pad)?;
        self.update(pad, OUTPUT, 0)
    }
    pub fn direction_output(&mut self, pad: Pad, high: bool) -> Result<(), Error> {
        self.check(pad)?;
        if self.read(pad)? & (ENABLE | UNMASK) != 0 {
            return Err(Error::InterruptActive);
        }
        // Value and output-enable share the same 32-bit register publication.
        self.update(pad, OUTPUT | VALUE, OUTPUT | if high { VALUE } else { 0 })
    }
    pub fn set_output(&mut self, pad: Pad, high: bool) -> Result<(), Error> {
        self.check(pad)?;
        if self.read(pad)? & OUTPUT == 0 {
            return Err(Error::Direction);
        }
        self.update(pad, VALUE, if high { VALUE } else { 0 })
    }
    pub fn pull(&mut self, pad: Pad, pull: Pull) -> Result<(), Error> {
        self.check(pad)?;
        let bits = match pull {
            Pull::Disabled => 0,
            Pull::Up => 1 << 20,
            Pull::Down => 1 << 21,
        };
        self.update(pad, PULL, bits)
    }
    /// Source's two-bit drive-strength encoding; no unverified mA mapping.
    pub fn drive_strength(&mut self, pad: Pad, encoding: u8) -> Result<(), Error> {
        self.check(pad)?;
        if encoding > 3 {
            return Err(Error::InvalidDriveStrength);
        }
        self.update(pad, 3 << 17, u32::from(encoding) << 17)
    }
    /// Select a raw source-backed function index, without assuming which
    /// function is GPIO for a particular board. Only pads0..144 have the
    /// pinned donor's individual four-function mux groups.
    pub fn mux(&mut self, pad: Pad, function: u8) -> Result<(), Error> {
        self.check(pad)?;
        if pad.0 > 144 || function > 3 {
            return Err(Error::InvalidMux);
        }
        if self.read(pad)? & (OUTPUT | ENABLE | UNMASK) != 0 {
            return Err(Error::InterruptActive);
        }
        let before = match self.registers.read_mux(pad.0) {
            Err(Error::MissingMux) => return Err(Error::MissingMux),
            result => {
                if result.is_err() {
                    self.fault = true;
                }
                result?
            }
        };
        if before == 0xff {
            return Err(Error::InvalidMux);
        }
        self.saved_mux[usize::from(pad.0)].get_or_insert(before);
        // Preserve unspecified upper byte bits, unlike a blanket write index.
        let wanted = (before & !3) | function;
        self.access(|r| r.write_mux(pad.0, wanted))?;
        if self.access(|r| r.read_mux(pad.0))? != wanted {
            self.fault = true;
            return Err(Error::Readback);
        }
        Ok(())
    }
    /// Linux's exact time-bin encoding (microseconds); no extra timing
    /// precision is claimed. Pin0's internal-debounce bit overrides it.
    pub fn debounce(&mut self, pad: Pad, mut micros: u32) -> Result<(), Error> {
        self.check(pad)?;
        if micros >= 1_000_000 {
            return Err(Error::InvalidDebounce);
        }
        if pad.0 == 0 && self.access(|r| r.read32(MASTER))? & INTERNAL_DEBOUNCE != 0 {
            micros = 0;
        }
        let bits = match micros {
            0 => 0,
            1..=60 => 0x60 | 1,
            61..=975 => 0x60 | ((micros / 61) & 15),
            976..=3899 => 0x70 | ((micros / 244) & 15),
            3900..=249_999 => 0xe0 | ((micros / 15_625) & 15),
            _ => 0xf0 | ((micros / 62_500) & 15),
        };
        // Debounce writes can suppress IRQ_ENABLE reads on every pad. Use the
        // same masked enable/readback settlement as irq_set_type, bounded.
        self.settle(pad, DEBOUNCE, bits)
    }
    fn settle(&mut self, pad: Pad, mask: u32, bits: u32) -> Result<(), Error> {
        // MaskStsEn suppression is controller-wide. Do not disturb an unowned
        // firmware IRQ or an active sibling while changing debounce/type. A
        // future native owner must also serialize firmware/OpRegion access;
        // this register inventory is not a replacement for that lease.
        for number in 0..PADS as u8 {
            let Ok(other) = Pad::new(number) else {
                continue;
            };
            if other == pad {
                continue;
            }
            let control = self.read(other)?;
            if !contains(&self.owned, other) && control & WAKE_POLICY != 0 {
                return Err(Error::FirmwareWake);
            }
            if !contains(&self.owned, other) && control & (ENABLE | UNMASK) != 0 {
                return Err(Error::FirmwareInterrupt);
            }
            if contains(&self.owned, other) && control & UNMASK != 0 {
                return Err(Error::InterruptActive);
            }
        }
        let before = self.read(pad)?;
        if before & UNMASK != 0 {
            return Err(Error::InterruptActive);
        }
        let final_value = (before & !(mask | STATUS)) | bits;
        self.write(pad, (final_value | ENABLE) & !UNMASK)?;
        let mut settled = false;
        for _ in 0..SETTLE_READS {
            if self.read(pad)? & ENABLE != 0 {
                settled = true;
                break;
            }
        }
        if !settled {
            self.fault = true;
            return Err(Error::DebounceTimeout);
        }
        self.write(pad, final_value)?;
        if self.read(pad)? & !(INPUT | STATUS) != final_value & !(INPUT | STATUS) {
            self.fault = true;
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub fn interrupt_type(&mut self, pad: Pad, kind: Interrupt) -> Result<(), Error> {
        self.check(pad)?;
        if self.read(pad)? & OUTPUT != 0 {
            return Err(Error::Direction);
        }
        self.settle(pad, LEVEL | POLARITY, kind.bits())
    }
    pub fn interrupt_enable(&mut self, pad: Pad, unmask: bool) -> Result<(), Error> {
        self.check(pad)?;
        if self.read(pad)? & OUTPUT != 0 {
            return Err(Error::Direction);
        }
        self.update(
            pad,
            ENABLE | UNMASK,
            ENABLE | if unmask { UNMASK } else { 0 },
        )
    }
    pub fn interrupt_mask(&mut self, pad: Pad) -> Result<(), Error> {
        self.check(pad)?;
        self.update(pad, UNMASK, 0)
    }
    pub fn interrupt_disable(&mut self, pad: Pad) -> Result<(), Error> {
        self.check(pad)?;
        self.update(pad, ENABLE | UNMASK, 0)
    }
    /// Bounded demultiplex: one summary snapshot, four pins per bit, at most
    ///183 callbacks. The consumer handles the device before fresh RMW
    ///acknowledgement. New pending bits are never cleared by ordinary updates.
    ///A reasserted cause is masked after ACK to bound interrupt storms, and
    ///reported for explicit deferred recovery. Unowned pins are untouched.
    pub fn service(
        &mut self,
        mut consumer: impl FnMut(Pad, Pending) -> Result<(), Error>,
    ) -> ServiceReport {
        let mut report = ServiceReport {
            delivered: [0; 3],
            storm_masked: [0; 3],
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
        consumer: &mut impl FnMut(Pad, Pending) -> Result<(), Error>,
        report: &mut ServiceReport,
    ) -> Result<(), Error> {
        let high = self.access(|r| r.read32(SUMMARY_HI))?;
        let low = self.access(|r| r.read32(SUMMARY_LO))?;
        let summary = ((u64::from(high) << 32) | u64::from(low)) & ((1u64 << 46) - 1);
        for number in 0..PADS as u8 {
            let Ok(pad) = Pad::new(number) else { continue };
            if !contains(&self.owned, pad) || summary & (1 << (number / 4)) == 0 {
                continue;
            }
            let pending = self.read(pad)?;
            if pending & STATUS == 0 || pending & UNMASK == 0 {
                continue;
            }
            // Level sources are masked through the whole consumer.
            let level = pending & LEVEL != 0;
            if level {
                self.update(pad, UNMASK, 0)?;
            }
            if consumer(
                pad,
                Pending {
                    interrupt: pending & (1 << 28) != 0,
                    wake: pending & (1 << 29) != 0,
                },
            )
            .is_err()
            {
                // Consumer failure leaves the source masked; pending
                // architectural status is not silently acknowledged.
                self.update(pad, UNMASK, 0)?;
                return Err(Error::Consumer);
            }
            insert(&mut report.delivered, pad);
            let current = self.read(pad)?;
            // ACK only the causes captured for this delivery. Preserve fresh
            // controls and a different cause arriving during the callback.
            self.write(pad, (current & !STATUS) | (pending & STATUS))?;
            let after = self.read(pad)?;
            if after & STATUS != 0 {
                self.update(pad, UNMASK, 0)?;
                insert(&mut report.storm_masked, pad);
            } else if level {
                self.update(pad, UNMASK, UNMASK)?;
            }
        }
        let master = self.access(|r| r.read32(MASTER))?;
        self.access(|r| r.write32(MASTER, master | EOI))?;
        // Readback flushes the posted master write; EOI is a command, not a
        // made-up sticky completion bit or CPU/APIC EOI acknowledgement.
        let _ = self.access(|r| r.read32(MASTER))?;
        Ok(())
    }
    /// Mask/disable and restore only this controller's original owned pad
    ///controls. No global reset, firmware wake clearing or neighboring writes.
    ///A failure keeps every original transport owner and can be retried;
    ///normal I/O remains faulted throughout an uncertain retirement.
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.retired {
            return Ok(());
        }
        self.fault = true;
        if self.restored {
            self.access(|r| r.finish())?;
            self.retired = true;
            return Ok(());
        }
        for number in 0..PADS as u8 {
            let Ok(pad) = Pad::new(number) else { continue };
            if !contains(&self.owned, pad) {
                continue;
            }
            self.update(pad, ENABLE | UNMASK, 0)?;
        }
        for number in 0..PADS as u8 {
            let Ok(pad) = Pad::new(number) else { continue };
            if !contains(&self.owned, pad) {
                continue;
            }
            self.update(pad, OUTPUT, 0)?;
            if let Some(mux) = self.saved_mux[usize::from(number)] {
                self.access(|r| r.write_mux(number, mux))?;
                if self.access(|r| r.read_mux(number))? != mux {
                    return Err(Error::Readback);
                }
            }
            let saved = self.saved[usize::from(number)];
            self.write(pad, saved)?;
            if self.read(pad)? & !(STATUS | INPUT) != saved {
                return Err(Error::Readback);
            }
        }
        self.restored = true;
        self.access(|r| r.finish())?;
        self.retired = true;
        Ok(())
    }
}
impl<R: RegisterIo> Drop for Controller<R> {
    fn drop(&mut self) {
        if self.retired {
            // SAFETY: no registration exists in this protocol-only cut; all
            // serialized callers stopped and pad restoration succeeded.
            unsafe { ManuallyDrop::drop(&mut self.registers) };
        }
        // Otherwise leave the owner kept, including failed effects.
    }
}
