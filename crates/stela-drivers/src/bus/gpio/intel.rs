// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 Intel Corporation
// Authors: Mathias Nyman <mathias.nyman@linux.intel.com>
//          Mika Westerberg <mika.westerberg@linux.intel.com>
// Copyright (c) 2026 Stela contributors
//! Modern Intel community-based GPIO/pinctrl register protocols.
//!
//! Profile matching describes the original tables; it grants no device, pad,
//! firmware or interrupt ownership. Raw constructors remain internal to the
//! actual native ACPI/MMIO adapter and independent peers. That adapter serves
//! ordinary GPIO OpRegions; these serialized process/deferred operations do not
//! install a parent interrupt. Lynx Point, Bay Trail and Cherryview use different engines
//! and are deliberately absent from this modern register interface.
mod engine;
mod registers;
mod tables;
pub use engine::{Controller, Direction, Interrupt, Pull, ServiceReport};
pub use registers::{NativeRegisters, RegisterIo};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Mapping,
    Allocation,
    InvalidProfile,
    InvalidPad,
    UnownedPad,
    FirmwareOwner,
    FirmwareInterrupt,
    AcpiInterrupt,
    Locked,
    TxLocked,
    Readback,
    Unsupported,
    InvalidPull,
    InvalidDebounce,
    Direction,
    InterruptActive,
    Faulted,
    Retired,
    Consumer,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Group {
    register: u16,
    first: u16,
    count: u16,
    gpio: i16,
    pad_own: u16,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Community {
    bar: u8,
    first: u16,
    count: u16,
    pad_own: usize,
    lock: usize,
    host_own: usize,
    status: usize,
    enable: usize,
    groups: &'static [Group],
}

/// Exact original ACPI/UID and community/group description, not admission.
#[derive(Debug)]
pub struct Profile {
    name: &'static str,
    uid: Option<&'static str>,
    communities: &'static [Community],
}
impl Profile {
    #[cfg(feature = "native-acpi")]
    pub(in crate::bus::gpio) fn resource_bars(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.communities.iter().map(|community| community.bar)
    }
    pub fn from_acpi(hid: &str, uid: Option<&str>) -> Option<&'static Self> {
        tables::MATCHES.iter().find_map(|(id, profile)| {
            (*id == hid && profile.uid.is_none_or(|value| Some(value) == uid)).then_some(*profile)
        })
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    /// Source GPIO numbering includes explicit gaps and NOMAP groups.
    pub fn gpio_to_pad(&self, gpio: u16) -> Option<u16> {
        for community in self.communities {
            for group in community.groups {
                if let Ok(base) = u16::try_from(group.gpio)
                    && gpio >= base
                    && gpio - base < group.count
                {
                    return Some(group.first + gpio - base);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
