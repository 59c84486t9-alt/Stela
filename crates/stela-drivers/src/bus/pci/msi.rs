// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig.
// Copyright (c) 2026 Stela contributors
//! Single-message PCI MSI configuration with kept real config ownership.
//! Register layouts and narrow message programming follow Linux PCI MSI at
//! a804c5742bff224d4cb4d25dd383554d598be32b. Ownership, validation, readback and
//! quarantine are Stela integration. This is not an IRQ controller or DMA stop.
use super::{Address, ConfigSpace, EcamConfig, Function, capability, capability::CapabilityError};
use crate::bus::irq::MsiMessage;
use alloc::sync::Arc;
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};

mod retirement;
pub use retirement::DisabledMsiConfig;

const COMMAND: u16 = 4;
#[cfg(test)]
const STATUS: u16 = 6;
const INTX_DISABLE: u16 = 1 << 10;
#[cfg(test)]
const CAP_LIST: u16 = 1 << 4;
const MSI: u8 = 5;
const MSIX: u8 = 0x11;
const ENABLE: u16 = 1;
const MMC: u16 = 7 << 1;
const MME: u16 = 7 << 4;
const WIDE: u16 = 1 << 7;
const MASK_CAPABLE: u16 = 1 << 8;
const MSIX_ENABLE: u16 = 1 << 15;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// A transport whose `write16` has the native word-store effect.
///
/// # Safety
/// Configuration reads/writes have real serialized effects. In particular,
/// `write16` never replays adjacent Status W1C bits through a dword RMW. It
/// must override the generic model fallback. Access remains valid under the
/// enclosing owner and occurs only in process/deferred context.
pub unsafe trait MsiConfigSpace: ConfigSpace {}
// SAFETY: EcamConfig overrides write16 with Mmio::write16, a native volatile
// word store; its real mapped/config lifetime is the constructor's grant.
unsafe impl MsiConfigSpace for EcamConfig {}

pub type RetainedOwner = Arc<dyn Any + Send + Sync>;
pub type Released<C> = (Function<C>, RetainedOwner);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsiError {
    MissingCapability,
    MalformedCapability,
    Unsupported,
    ActiveMsi,
    ActiveMsix,
    IdentityChanged,
    CapabilityChanged,
    InvalidMessage,
    FailedRead { offset: u16 },
    Readback { offset: u16 },
    NotProgrammed,
    TerminalRetirement,
    StopAlreadyAttempted,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Layout {
    offset: u16,
    header: u16,
    features: u16,
}
impl Layout {
    fn wide(self) -> bool {
        self.features & WIDE != 0
    }
    fn data(self) -> u16 {
        self.offset + if self.wide() { 12 } else { 8 }
    }
    fn mask(self) -> Option<u16> {
        (self.features & MASK_CAPABLE != 0)
            .then_some(self.offset + if self.wide() { 16 } else { 12 })
    }
}
impl From<CapabilityError> for MsiError {
    fn from(error: CapabilityError) -> Self {
        match error {
            CapabilityError::FailedRead { offset } => Self::FailedRead { offset },
            _ => Self::MalformedCapability,
        }
    }
}
fn read16<C: ConfigSpace>(c: &C, offset: u16) -> Result<u16, MsiError> {
    let value = c.read16(offset);
    if value == u16::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Ok(value)
    }
}
fn verify16<C: MsiConfigSpace>(c: &C, offset: u16, expected: u16) -> Result<(), MsiError> {
    let actual = c.read16(offset);
    if actual == expected {
        Ok(())
    } else if actual == u16::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Err(MsiError::Readback { offset })
    }
}
fn verify32<C: MsiConfigSpace>(c: &C, offset: u16, expected: u32) -> Result<(), MsiError> {
    let actual = c.read32(offset);
    if actual == expected {
        Ok(())
    } else if actual == u32::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Err(MsiError::Readback { offset })
    }
}
fn write16<C: MsiConfigSpace>(c: &mut C, offset: u16, value: u16) -> Result<(), MsiError> {
    c.write16(offset, value);
    verify16(c, offset, value)
}
fn write32<C: MsiConfigSpace>(c: &mut C, offset: u16, value: u32) -> Result<(), MsiError> {
    c.write32(offset, value);
    verify32(c, offset, value)
}

fn discover<C: MsiConfigSpace>(f: &mut Function<C>) -> Result<(Layout, u16), MsiError> {
    let expected = u32::from(f.vendor) | u32::from(f.device) << 16;
    let c = f.config();
    let id = c.read32(0);
    if id == u32::MAX {
        return Err(MsiError::FailedRead { offset: 0 });
    }
    if id != expected {
        return Err(MsiError::IdentityChanged);
    }
    let header_type = c.read8(0x0e) & 0x7f;
    if !matches!(header_type, 0 | 1) {
        return Err(MsiError::Unsupported);
    }
    // The walk reads Status; without a capability list nothing is found.
    let mut found = None;
    let mut msix = false;
    for entry in c.capabilities() {
        let entry = entry?;
        let offset = entry.offset;
        match entry.id {
            MSI => {
                if found.is_some() {
                    return Err(MsiError::MalformedCapability);
                }
                let control = read16(c, offset + 2)?;
                // Extended message data and reserved queue encodings need their
                // own contract; never truncate them to a successful 16-bit MSI.
                if control & !(ENABLE | MMC | MME | WIDE | MASK_CAPABLE) != 0
                    || (control & MMC) >> 1 > 5
                    || (control & MME) >> 4 > (control & MMC) >> 1
                {
                    return Err(MsiError::Unsupported);
                }
                let layout = Layout {
                    offset,
                    header: entry.header,
                    features: control & !(ENABLE | MME),
                };
                found = Some((layout, control));
            }
            MSIX => {
                if core::mem::replace(&mut msix, true) {
                    return Err(MsiError::MalformedCapability);
                }
                if read16(c, offset + 2)? & MSIX_ENABLE != 0 {
                    return Err(MsiError::ActiveMsix);
                }
            }
            0 => return Err(MsiError::MalformedCapability),
            _ if entry.layout == capability::Layout::Unsupported => {
                return Err(MsiError::Unsupported);
            }
            _ => {}
        }
    }
    found.ok_or(MsiError::MissingCapability)
}

/// Owns the original Function and kept PCI/config/root/reset epoch.
/// There is no normal config escape or second enumeration. Terminal retirement
/// separately permits one unsafe scoped device-stop operation. No MSI method changes BM,
/// acknowledges a device cause, drains callbacks, or infers DMA coherency.
/// Operations and final release require process/deferred context, never an ISR.
pub struct MsiConfig<C: MsiConfigSpace = EcamConfig> {
    owner: Option<Released<C>>,
    layout: Layout,
    message: Option<MsiMessage>,
    terminal: bool,
}
impl<C: MsiConfigSpace> MsiConfig<C> {
    /// # Safety
    /// `function` is the unique function (unmodified identity/address),
    /// and `retained` is its config/root/PCI/reset-epoch owner, not a
    /// dummy token. This keeps the real mapped configuration transport even
    /// if abandoned. Native config accesses and every source/worker/reset are
    /// serialized; no firmware/alias/other CPU can reconfigure or revoke it.
    /// Old MSI/INTx delivery, callbacks and device work have drained;
    /// initially disabled MSI alone does not establish this. The platform has
    /// checked MSI routing. No vector or requester-coherency grant is created.
    /// Errors return both owners without modifying configuration.
    pub unsafe fn new(
        mut function: Function<C>,
        retained: RetainedOwner,
    ) -> Result<Self, (MsiError, Released<C>)> {
        match discover(&mut function) {
            Ok((layout, control)) if control & ENABLE == 0 => Ok(Self {
                owner: Some((function, retained)),
                layout,
                message: None,
                terminal: false,
            }),
            Ok(_) => Err((MsiError::ActiveMsi, (function, retained))),
            Err(error) => Err((error, (function, retained))),
        }
    }
    pub fn address(&self) -> Result<Address, MsiError> {
        Ok(self.owner.as_ref().ok_or(MsiError::Released)?.0.address)
    }
    fn normal(&self) -> Result<(), MsiError> {
        if self.terminal {
            Err(MsiError::TerminalRetirement)
        } else if self.owner.is_none() {
            Err(MsiError::Released)
        } else {
            Ok(())
        }
    }
    /// Irreversibly disable MSI and fallback INTx before a device stop that
    /// needs the original configuration owner. This establishes no DMA, posted
    /// write, IRQ or worker completion. The registry keeps its route/callbacks
    /// while the terminal owner performs the real source stop.
    ///
    /// Authorization is revoked before even the first configuration access.
    /// Failure keeps the owner here with no program/unmask/retry path.
    /// Ordinary admission-time mask remains reversible and does not use this.
    pub fn begin_device_retirement(&mut self) -> Result<DisabledMsiConfig<C>, MsiError> {
        self.normal()?;
        self.terminal = true;
        self.message = None;
        self.mask_inner()?;
        Ok(DisabledMsiConfig::new(
            self.owner.take().ok_or(MsiError::Released)?,
        ))
    }
    fn checked(&mut self) -> Result<u16, MsiError> {
        let f = &mut self.owner.as_mut().ok_or(MsiError::Released)?.0;
        let (layout, control) = discover(f)?;
        if layout != self.layout {
            return Err(MsiError::CapabilityChanged);
        }
        Ok(control)
    }
    fn config(&mut self) -> Result<&mut C, MsiError> {
        Ok(self.owner.as_mut().ok_or(MsiError::Released)?.0.config())
    }
    fn mask_inner(&mut self) -> Result<(), MsiError> {
        let control = self.checked()?;
        let layout = self.layout;
        let c = self.config()?;
        // Establish INTxDisable before clearing MSI Enable: clearing Enable
        // first can expose fallback legacy INTx while route state is changing.
        let command = read16(c, COMMAND)?;
        write16(c, COMMAND, command | INTX_DISABLE)?;
        if let Some(offset) = layout.mask() {
            let mask = c.read32(offset);
            // All-ones is a valid mask bitmap. Presence/control reads check
            // this transport; never interpret valid all-masked as failed data.
            write32(c, offset, mask | 1)?;
        }
        write16(c, layout.offset + 2, control & !ENABLE)
    }
    /// Mask and acknowledge MSI plus fallback INTx. This does not stop a device
    /// or drain already posted writes, callbacks, timers or deferred work.
    pub fn mask(&mut self) -> Result<(), MsiError> {
        self.normal()?;
        let result = self.mask_inner();
        if result.is_err() {
            self.message = None;
        }
        result
    }
    /// Disable the route and forget its authorization for subsequent unmask.
    /// Unrelated command/control/mask bits and message fields are preserved.
    pub fn disable(&mut self) -> Result<(), MsiError> {
        self.message = None;
        self.mask()
    }
    /// Program exactly one supplied message, while MSI and INTx are disabled.
    ///
    /// # Safety
    /// This typed message belongs to the registry's checked route;
    /// every callback/resource remains held. Reprogramming requires real
    /// source/callback/posted-write drain; masking alone is insufficient.
    pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), MsiError> {
        self.normal()?;
        if message.address & 3 != 0
            || message.data > u32::from(u16::MAX)
            || (!self.layout.wide() && message.address > u64::from(u32::MAX))
        {
            return Err(MsiError::InvalidMessage);
        }
        self.message = None;
        self.mask()?;
        let layout = self.layout;
        let control = self.checked()? & !(ENABLE | MME);
        let c = self.config()?;
        write16(c, layout.offset + 2, control)?;
        write32(c, layout.offset + 4, message.address as u32)?;
        if layout.wide() {
            write32(c, layout.offset + 8, (message.address >> 32) as u32)?;
        }
        write16(c, layout.data(), message.data as u16)?;
        verify16(c, layout.offset + 2, control)?;
        self.message = Some(message);
        Ok(())
    }
    /// # Safety
    /// The registry keeps/publishes the callback and checked route;
    /// the requester and all IRQ/DMA/work/reset owners remain held. BM and
    /// vendor source enable are separately controlled by that owner.
    pub unsafe fn unmask(&mut self) -> Result<(), MsiError> {
        self.normal()?;
        let message = self.message.ok_or(MsiError::NotProgrammed)?;
        self.mask()?;
        let layout = self.layout;
        let control = self.checked()?;
        let result = (|| {
            let c = self.config()?;
            verify32(c, layout.offset + 4, message.address as u32)?;
            if layout.wide() {
                verify32(c, layout.offset + 8, (message.address >> 32) as u32)?;
            }
            verify16(c, layout.data(), message.data as u16)?;
            if control & MME != 0 {
                return Err(MsiError::CapabilityChanged);
            }
            if let Some(offset) = layout.mask() {
                let mask = c.read32(offset);
                write32(c, offset, mask & !1)?;
            }
            write16(c, layout.offset + 2, control | ENABLE)
        })();
        if result.is_err() {
            self.message = None;
        }
        result
    }
    /// Return the owners only after independent source/IRQ/work drain.
    ///
    /// # Safety
    /// The device is stopped, posted MSI writes/CPU pending vectors,
    /// callbacks and all deferred/timer/reset users have drained and cannot
    /// restart. Every DMA lease/fence/IOTLB obligation remains independently
    /// owned until completed; this helper does not prove any of them.
    pub unsafe fn release(&mut self) -> Result<Released<C>, MsiError> {
        self.disable()?;
        self.owner.take().ok_or(MsiError::Released)
    }
}
impl<C: MsiConfigSpace> Drop for MsiConfig<C> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // No hardware access or guessed completion in Drop. Keep the
            // real configuration and root owner on every uncertain path.
            core::mem::forget(owner);
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
        }
    }
}
/// Cumulative abandoned config/root owners, kept for safety.
pub fn quarantined_configurations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests;
