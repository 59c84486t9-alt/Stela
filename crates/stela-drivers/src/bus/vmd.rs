// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Intel Volume Management Device host bridge. This is a PCI configuration and
//! resource-routing backend, never an Intel RST RAID-volume implementation.
//!
//! Physical attachment uses actual stopped PCI ownership and UC mappings. DMA
//! requester aliases and native child-driver attachment require the platform's
//! independently owned VMD DMA domain; this module never invents an identity
//! domain or enables a child bus master on the strength of a numeric BDF.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

mod config;
mod native;
pub mod nvme;
pub mod remap;
mod source;
pub use config::ChildConfig;
pub use native::{NativeRegisters, NativeResources};
pub use source::{ChildSource, ParentSource, RetiredHandle};

const VMCAP: u16 = 0x40;
const VMCONFIG: u16 = 0x44;
const VMLOCK: u16 = 0x70;
const COMMAND: u16 = 4;
const MEMORY: u16 = 2;
const BUS_MASTER: u16 = 4;
const INTX_DISABLE: u16 = 1 << 10;
const MSI_BYPASS: u16 = 2;
const VENDOR_CAPABILITY: u8 = 9;
const VENDOR_HEADER_BYTES: u16 = 3;
const SHADOW_SIGNATURE_BYTES: u16 = 8;
const SHADOW_CAPABILITY_BYTES: u16 = 24;
const SHADOW_SIGNATURE: u32 = 0x5348_4457;
const BUS_BYTES: u64 = 1 << 20;
static NEXT_DOMAIN: AtomicU32 = AtomicU32::new(0x1_0000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedDevice,
    InvalidResource,
    Mapping,
    ReadFailed,
    Readback,
    Address,
    Capability,
    Exhausted,
    Suspended,
    Quarantined,
    ActiveChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    shadow: Shadow,
    restrictions: bool,
    pub first_vector: u8,
    pub can_bypass_remap: bool,
    pub bios_pm_quirk: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shadow {
    Vendor,
    Native,
    Bios,
}
impl Profile {
    pub fn identify(vendor: u16, device: u16) -> Result<Self, Error> {
        if vendor != 0x8086 {
            return Err(Error::UnsupportedDevice);
        }
        Ok(match device {
            0x201d => Self {
                shadow: Shadow::Vendor,
                restrictions: false,
                first_vector: 0,
                can_bypass_remap: false,
                bios_pm_quirk: false,
            },
            0x28c0 => Self {
                shadow: Shadow::Native,
                restrictions: true,
                first_vector: 0,
                can_bypass_remap: true,
                bios_pm_quirk: false,
            },
            0x28c1 => Self {
                shadow: Shadow::Bios,
                restrictions: false,
                first_vector: 0,
                can_bypass_remap: true,
                bios_pm_quirk: false,
            },
            0x467f | 0x4c3d | 0xa77f | 0x7d0b | 0xad0b | 0x9a0b | 0xb60b | 0xb06f | 0xb07f
            | 0xd70b | 0xd73b => Self {
                shadow: Shadow::Vendor,
                restrictions: true,
                first_vector: 1,
                can_bypass_remap: false,
                bios_pm_quirk: true,
            },
            _ => return Err(Error::UnsupportedDevice),
        })
    }
}

/// One native reserved aperture; `bus_start` incorporates hardware shadow
/// translation. Bounds are half open. These numbers grant no reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    pub cpu_start: u64,
    pub bus_start: u64,
    pub bytes: u64,
    pub prefetchable: bool,
}
impl Window {
    pub fn translate(&self, bus: u64, bytes: u64) -> Result<u64, Error> {
        let local = bus.checked_sub(self.bus_start).ok_or(Error::Address)?;
        if bytes == 0 || local.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err(Error::Address);
        }
        self.cpu_start.checked_add(local).ok_or(Error::Address)
    }
}

/// Native hardware effects. Tests may implement this with a register model.
///
/// # Safety
/// Own the actual VMD parent config, all three reserved BARs and current child
/// hierarchy epoch. All firmware/other-driver users and child DMA/IRQ/work are
/// stopped and drained before construction. Each access is a native aligned
/// width; child writes include an equal-width readback to flush VMD's posted
/// config writes. No config access occurs from IRQ context or outside the sole
/// mutable host owner; this exclusion serializes the entire CFGBAR, not each
/// child separately. A failed effect must retain the original owners.
/// The original stopped-requester owner qualifies the complete standard
/// capability framing before native attachment; vendor Length fields still
/// bound every vendor-specific read performed here.
pub unsafe trait Registers {
    fn parent_read(&mut self, offset: u16, width: u8) -> Result<u32, Error>;
    fn parent_write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error>;
    fn bar(&self, index: u8) -> (u64, u64, bool);
    fn shadow_read(&mut self, offset: usize) -> Result<u64, Error>;
    fn child_read(&mut self, offset: usize, width: u8) -> Result<u32, Error>;
    fn child_write(&mut self, offset: usize, width: u8, value: u32) -> Result<(), Error>;
    fn table_read(&mut self, offset: u64) -> Result<u32, Error>;
    fn table_write(&mut self, offset: u64, value: u32) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub domain: u32,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Child {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: [u8; 3],
    pub header: u8,
}

pub struct Host<R: Registers> {
    registers: Option<R>,
    identity: u32,
    profile: Profile,
    domain: u32,
    first_bus: u8,
    last_bus: u8,
    windows: [Window; 2],
    membar2_reserved: u64,
    live: bool,
    poisoned: bool,
    programmed_vectors: Option<u16>,
    remap_layout: Option<remap::Layout>,
}
impl<R: Registers> Host<R> {
    /// Initialize the actual aperture without enabling bus mastering. All
    /// children must have a genuine firmware/takeover stopped grant. The
    /// original owners are returned only on failure before any hardware effect.
    pub fn initialize(mut registers: R) -> Result<Self, (Error, Option<R>)> {
        let prepared = (|| {
            let id = registers.parent_read(0, 4)?;
            let profile = Profile::identify(id as u16, (id >> 16) as u16)?;
            if registers.parent_read(0x0e, 1)? & 0x7f != 0 {
                return Err(Error::InvalidResource);
            }
            // VMD uses the three 64-bit BAR pairs 0/1, 2/3 and 4/5. Check
            // actual config against the original reservation before touching
            // decode or accepting a shadow translation. The reservation
            // authority, rather than probing live child windows, owns sizing.
            for index in [0, 2, 4] {
                let offset = 0x10 + u16::from(index) * 4;
                let low = registers.parent_read(offset, 4)?;
                let high = registers.parent_read(offset + 4, 4)?;
                let (base, bytes, prefetchable) = registers.bar(index);
                if low & 7 != 4
                    || (u64::from(high) << 32 | u64::from(low & !15)) != base
                    || (low & 8 != 0) != prefetchable
                    || bytes == 0
                    || base.checked_add(bytes).is_none()
                {
                    return Err(Error::InvalidResource);
                }
            }
            let (_, cfgbytes, _) = registers.bar(0);
            if cfgbytes < BUS_BYTES || !cfgbytes.is_multiple_of(BUS_BYTES) {
                return Err(Error::InvalidResource);
            }
            let command = registers.parent_read(COMMAND, 2)? as u16;
            if command == u16::MAX || command & BUS_MASTER != 0 {
                return Err(Error::ActiveChild);
            }
            let domain = NEXT_DOMAIN
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    n.checked_add(1).filter(|next| *next <= i32::MAX as u32)
                })
                .map_err(|_| Error::Exhausted)?;
            Ok((profile, command, domain, id))
        })();
        let (profile, command, domain, identity) = match prepared {
            Ok(p) => p,
            Err(e) => return Err((e, Some(registers))),
        };
        // Once decoding may have changed, no failure can release the hierarchy.
        let mut host = Self {
            registers: Some(registers),
            identity,
            profile,
            domain,
            first_bus: 0,
            last_bus: 0,
            windows: [Window {
                cpu_start: 0,
                bus_start: 0,
                bytes: 0,
                prefetchable: false,
            }; 2],
            membar2_reserved: 0,
            live: true,
            poisoned: false,
            programmed_vectors: None,
            remap_layout: None,
        };
        let result = (|| {
            host.parent_write_checked(COMMAND, command | MEMORY | INTX_DISABLE)?;
            host.discover()?;
            // Remapping remains enabled until an actual parent MSI-X/domain
            // owner is attached. No child IRQ may be unmasked by this host.
            host.set_remapping(true)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(host),
            Err(e) => {
                host.poisoned = true;
                Err((e, None))
            }
        }
    }
    fn io(&mut self) -> &mut R {
        self.registers.as_mut().expect("retained VMD hardware")
    }
    fn parent_write_checked(&mut self, offset: u16, value: u16) -> Result<(), Error> {
        self.io().parent_write(offset, 2, u32::from(value))?;
        if self.io().parent_read(offset, 2)? != u32::from(value) {
            return Err(Error::Readback);
        }
        Ok(())
    }
    fn discover(&mut self) -> Result<(), Error> {
        let mut shadow = [None; 2];
        let reserved = match self.profile.shadow {
            Shadow::Bios => {
                shadow = [
                    Some(self.io().shadow_read(0x2818)?),
                    Some(self.io().shadow_read(0x2820)?),
                ];
                self.first_bus = (self.io().shadow_read(0x2840)? >> 8) as u8;
                0x30d0
            }
            Shadow::Native => {
                let lock = self.io().parent_read(VMLOCK, 4)?;
                if lock == u32::MAX {
                    return Err(Error::ReadFailed);
                }
                if lock & 2 != 0 {
                    shadow = [
                        Some(self.io().shadow_read(0x2000)?),
                        Some(self.io().shadow_read(0x2008)?),
                    ];
                }
                0x2010
            }
            Shadow::Vendor => {
                shadow = self.vendor_shadow()?;
                0x2000
            }
        };
        self.membar2_reserved = reserved;
        if self.profile.restrictions {
            let cap = self.io().parent_read(VMCAP, 2)?;
            if cap == u32::from(u16::MAX) {
                return Err(Error::ReadFailed);
            }
            if cap & 1 != 0 {
                let config = self.io().parent_read(VMCONFIG, 2)?;
                if config == u32::from(u16::MAX) {
                    return Err(Error::ReadFailed);
                }
                self.first_bus = match (config >> 8) & 3 {
                    0 => 0,
                    1 => 128,
                    _ => 224,
                };
            }
        }
        let count = self.io().bar(0).1 / BUS_BYTES;
        let ecam_first = if self.profile.shadow == Shadow::Bios {
            u64::from(self.first_bus)
        } else {
            0
        };
        if ecam_first >= count {
            return Err(Error::InvalidResource);
        }
        self.last_bus = (u64::from(self.first_bus) + count - ecam_first - 1).min(255) as u8;
        for (i, bar) in [2, 4].into_iter().enumerate() {
            let (cpu, bytes, prefetchable) = self.io().bar(bar);
            let skip = if i == 1 { reserved } else { 0 };
            let bus = match shadow[i] {
                Some(value) if value != 0 || self.profile.shadow != Shadow::Bios => value & !15,
                _ => cpu,
            };
            if skip >= bytes {
                return Err(Error::InvalidResource);
            }
            self.windows[i] = Window {
                cpu_start: cpu.checked_add(skip).ok_or(Error::InvalidResource)?,
                bus_start: bus.checked_add(skip).ok_or(Error::InvalidResource)?,
                bytes: bytes - skip,
                prefetchable,
            };
            self.windows[i]
                .cpu_start
                .checked_add(bytes - skip)
                .ok_or(Error::InvalidResource)?;
            self.windows[i]
                .bus_start
                .checked_add(bytes - skip)
                .ok_or(Error::InvalidResource)?;
        }
        if self.windows[0].bus_start < self.windows[1].bus_start + self.windows[1].bytes
            && self.windows[1].bus_start < self.windows[0].bus_start + self.windows[0].bytes
        {
            return Err(Error::InvalidResource);
        }
        Ok(())
    }
    fn vendor_shadow(&mut self) -> Result<[Option<u64>; 2], Error> {
        if self.io().parent_read(6, 2)? & 0x10 == 0 {
            return Ok([None; 2]);
        }
        let mut offset = self.io().parent_read(0x34, 1)? as u16;
        let mut occupied = [false; 256];
        let mut first_vendor = true;
        let mut selected = None;
        while offset != 0 {
            if !(0x40..=0xfc).contains(&offset) || offset & 3 != 0 || occupied[usize::from(offset)]
            {
                return Err(Error::Capability);
            }
            let header = self.io().parent_read(offset, 2)?;
            if header == u32::from(u16::MAX) {
                return Err(Error::ReadFailed);
            }
            let vendor = header as u8 == VENDOR_CAPABILITY;
            let bytes = if vendor {
                let bytes = self.io().parent_read(offset + 2, 1)? as u16;
                if bytes < VENDOR_HEADER_BYTES {
                    return Err(Error::Capability);
                }
                bytes
            } else {
                // Native stopped-requester admission checks the other complete
                // capability bodies. Retain their headers here so a later
                // vendor extent cannot hide a previously traversed link.
                2
            };
            let end = offset
                .checked_add(bytes)
                .filter(|end| *end <= 256)
                .ok_or(Error::Capability)?;
            let span = &mut occupied[usize::from(offset)..usize::from(end)];
            if span.iter().any(|used| *used) {
                return Err(Error::Capability);
            }
            span.fill(true);
            let next = (header >> 8) as u16;
            if next != 0 && (offset..end).contains(&next) {
                return Err(Error::Capability);
            }
            if vendor && first_vendor {
                first_vendor = false;
                // Match the donor's first vendor capability, without reading
                // a signature outside its advertised payload.
                if bytes >= SHADOW_SIGNATURE_BYTES
                    && self.io().parent_read(offset + 4, 4)? == SHADOW_SIGNATURE
                {
                    if bytes < SHADOW_CAPABILITY_BYTES {
                        return Err(Error::Capability);
                    }
                    selected = Some(offset);
                }
            }
            offset = next;
        }
        // Follow the complete list before consuming addresses: a later link
        // back into the SHDW body must not turn register bytes into windows.
        let Some(offset) = selected else {
            return Ok([None; 2]);
        };
        let mut values = [None; 2];
        for (i, value) in values.iter_mut().enumerate() {
            let base = offset + 8 + i as u16 * 8;
            *value = Some(
                u64::from(self.io().parent_read(base, 4)?)
                    | u64::from(self.io().parent_read(base + 4, 4)?) << 32,
            );
        }
        Ok(values)
    }
    pub fn domain(&self) -> u32 {
        self.domain
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn buses(&self) -> core::ops::RangeInclusive<u8> {
        self.first_bus..=self.last_bus
    }
    pub fn windows(&self) -> &[Window; 2] {
        &self.windows
    }
    fn check_live(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Quarantined)
        } else if !self.live {
            Err(Error::Suspended)
        } else {
            Ok(())
        }
    }
    /// Actual child config is serialized by one mutable borrow of the whole
    /// host. The child cannot outlive, reset or retire its parent.
    pub fn config(
        &mut self,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<ChildConfig<'_, R>, Error> {
        self.check_live()?;
        if bus < self.first_bus || bus > self.last_bus || device >= 32 || function >= 8 {
            return Err(Error::Address);
        }
        let ecam_bus = if self.profile.shadow == Shadow::Bios {
            bus
        } else {
            bus - self.first_bus
        };
        let base = (usize::from(ecam_bus) << 20)
            | (usize::from(device) << 15)
            | (usize::from(function) << 12);
        let address = Address {
            domain: self.domain,
            bus,
            device,
            function,
        };
        Ok(ChildConfig {
            host: self,
            base,
            address,
        })
    }
    pub fn scan(&mut self) -> Result<Vec<Child>, Error> {
        config::scan(self)
    }
    /// # Safety
    /// All actual child DMA/IRQ/work has stopped and drained, and every native
    /// parent IRQ registration has retired, before entering platform sleep.
    /// Keep the entire resource/reset assignment and this owner across sleep.
    pub unsafe fn suspend(&mut self) -> Result<(), Error> {
        self.check_live()?;
        let result = (|| {
            self.disable_parent_vectors()?;
            self.set_remapping(true)?;
            let command = self.io().parent_read(COMMAND, 2)? as u16;
            if command == u16::MAX {
                return Err(Error::ReadFailed);
            }
            self.parent_write_checked(COMMAND, (command | INTX_DISABLE) & !(MEMORY | BUS_MASTER))
        })();
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.live = false;
        }
        result
    }
    /// Resume after the platform has really restored D0 and the exact parent
    /// resource assignment. Old IRQ registrations are not resurrected: native
    /// routes must be registered and programmed again before child restart.
    pub fn resume(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Quarantined);
        }
        if self.live {
            return Err(Error::ActiveChild);
        }
        let old_windows = self.windows;
        let old_buses = (self.first_bus, self.last_bus);
        let result = (|| {
            let id = self.io().parent_read(0, 4)?;
            if id != self.identity
                || Profile::identify(id as u16, (id >> 16) as u16)? != self.profile
            {
                return Err(Error::UnsupportedDevice);
            }
            for index in [0, 2, 4] {
                let offset = 0x10 + u16::from(index) * 4;
                let low = self.io().parent_read(offset, 4)?;
                let high = self.io().parent_read(offset + 4, 4)?;
                if low & 7 != 4
                    || (u64::from(high) << 32 | u64::from(low & !15)) != self.io().bar(index).0
                {
                    return Err(Error::InvalidResource);
                }
            }
            let command = self.io().parent_read(COMMAND, 2)? as u16;
            if command == u16::MAX || command & BUS_MASTER != 0 {
                return Err(Error::ActiveChild);
            }
            self.parent_write_checked(COMMAND, command | MEMORY | INTX_DISABLE)?;
            self.first_bus = 0;
            self.discover()?;
            if self.windows != old_windows || (self.first_bus, self.last_bus) != old_buses {
                return Err(Error::InvalidResource);
            }
            self.set_remapping(true)
        })();
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.live = true;
        }
        result
    }
    /// Configure VMD's hardware remap control, preserving bus restrictions.
    /// No bypass is admitted before the separate native IRQ and DMA authorities.
    fn set_remapping(&mut self, enabled: bool) -> Result<(), Error> {
        if self.profile.shadow == Shadow::Bios {
            return Ok(());
        }
        let value = self.io().parent_read(VMCONFIG, 2)? as u16;
        if value == u16::MAX {
            return Err(Error::ReadFailed);
        }
        self.parent_write_checked(
            VMCONFIG,
            if enabled {
                value & !MSI_BYPASS
            } else {
                value | MSI_BYPASS
            },
        )
    }
    /// # Safety
    /// Every child engine, DMA request, IRQ registration, CPU callback and work
    /// item is stopped/drained under its genuine native owner. No future access
    /// can begin. Parent disable never proves these child completion facts.
    pub unsafe fn retire(mut self) -> Result<R, Error> {
        self.check_live()?;
        let result = (|| {
            self.disable_parent_vectors()?;
            self.set_remapping(true)?;
            let command = self.io().parent_read(COMMAND, 2)? as u16;
            if command == u16::MAX {
                return Err(Error::ReadFailed);
            }
            self.parent_write_checked(COMMAND, (command | INTX_DISABLE) & !(MEMORY | BUS_MASTER))
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
        self.live = false;
        Ok(self.registers.take().unwrap())
    }
}
impl<R: Registers> Drop for Host<R> {
    fn drop(&mut self) {
        if let Some(registers) = self.registers.take() {
            core::mem::forget(registers);
        }
    }
}

#[cfg(test)]
mod tests;
