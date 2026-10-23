// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig
//! Owned single-vector MSI-X programming for native PCI devices.
//!
//! Layout/programming follows pinned Linux PCI MSI. The actual PCI/config/reset
//! and UC BAR mappings stay retained through failures. Masking is never a DMA,
//! device-cause, callback, posted-write or interrupt-controller drain proof.
use super::{
    Address, EcamConfig, Function,
    msi::{MsiConfigSpace, MsiError, RetainedOwner},
};
use crate::bus::{irq::MsiMessage, mmio::owned::PhysicalSpan};
use core::sync::atomic::{AtomicU64, Ordering};

mod discovery;
mod mapped;
use discovery::{Layout, discover};
pub use mapped::MappedBar;

const COMMAND: u16 = 4;
const INTX_DISABLE: u16 = 1 << 10;
const ENABLE: u16 = 1 << 15;
const FUNCTION_MASK: u16 = 1 << 14;
const ENTRY_BYTES: u64 = 16;
const VECTOR_MASK: u32 = 1;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoError;

/// Actual retained BAR resource and native accesses, including partial mappings.
/// # Safety
/// Metadata is immutable and describes an actually reserved complete BAR in the
/// same function/reset epoch as the enclosing PCI owner. `accessible` reports
/// real retained UC read/write mappings, not merely a numerically valid range.
/// Reads/writes are aligned native PCI DWORD effects and maintain required
/// ordering; errors may follow an effect. No competing driver/firmware may
/// relocate/reset/revoke/access the MSI-X table while this backing is retained.
pub unsafe trait BarAccess {
    fn physical_span(&self) -> PhysicalSpan;
    fn accessible(&self, offset: u64, bytes: u64) -> bool;
    fn read32(&self, offset: u64) -> Result<u32, IoError>;
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), IoError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Config(MsiError),
    MissingCapability,
    ActiveMsi,
    ActiveMsix,
    InvalidBar,
    InvalidTable,
    MemoryDisabled,
    Mapping,
    Io { bar: u8, offset: u64 },
    Readback { bar: u8, offset: u64 },
    InvalidMessage,
    NotProgrammed,
    CapabilityChanged,
    Quarantined,
    Released,
}
impl From<MsiError> for Error {
    fn from(error: MsiError) -> Self {
        Self::Config(error)
    }
}

pub type Owners<C, B> = (Function<C>, RetainedOwner, [Option<B>; 6]);

pub struct MsixConfig<C: MsiConfigSpace = EcamConfig, B: BarAccess = MappedBar> {
    owners: Option<Owners<C, B>>,
    layout: Layout,
    message: Option<MsiMessage>,
    poisoned: bool,
}
impl<C: MsiConfigSpace, B: BarAccess> MsixConfig<C, B> {
    /// # Safety
    /// Own the actual unique function/config/root/reset epoch and BAR resources,
    /// with memory decoding already enabled. BAR array indices are hardware
    /// BIRs. Retained ownership must be genuine, not an inert numeric token.
    /// Actual old MSI/MSI-X/INTx sources, callbacks, CPU pending/posted messages
    /// and work have drained. MSI-X disabled alone does not prove that. Native
    /// MSI routing must be qualified separately. Process/deferred context only.
    /// No hardware writes occur on constructor errors; all owners are returned.
    pub unsafe fn new(
        function: Function<C>,
        retained: RetainedOwner,
        bars: [Option<B>; 6],
    ) -> Result<Self, (Error, Owners<C, B>)> {
        let mut owners = (function, retained, bars);
        match discover(&mut owners.0, &owners.2) {
            Ok((layout, control)) if control & ENABLE == 0 => Ok(Self {
                owners: Some(owners),
                layout,
                message: None,
                poisoned: false,
            }),
            Ok(_) => Err((Error::ActiveMsix, owners)),
            Err(error) => Err((error, owners)),
        }
    }
    pub fn address(&self) -> Result<Address, Error> {
        Ok(self.owners.as_ref().ok_or(Error::Released)?.0.address)
    }
    pub fn vectors(&self) -> u16 {
        self.layout.vectors
    }
    pub fn needs_reset(&self) -> bool {
        self.poisoned
    }
    fn checked(&mut self) -> Result<u16, Error> {
        if self.poisoned {
            return Err(Error::Quarantined);
        }
        let owners = self.owners.as_mut().ok_or(Error::Released)?;
        let (layout, control) = discover(&mut owners.0, &owners.2)?;
        if layout != self.layout {
            return Err(Error::CapabilityChanged);
        }
        Ok(control)
    }
    fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.message = None;
            self.poisoned = true;
        }
        result
    }
    fn config_write(&mut self, offset: u16, value: u16) -> Result<(), Error> {
        let config = self.owners.as_mut().ok_or(Error::Released)?.0.config();
        config.write16(offset, value);
        let actual = config.read16(offset);
        if actual != value {
            return Err(Error::Config(if actual == u16::MAX {
                MsiError::FailedRead { offset }
            } else {
                MsiError::Readback { offset }
            }));
        }
        Ok(())
    }
    fn read(&self, bar: u8, offset: u64) -> Result<u32, Error> {
        self.owners.as_ref().ok_or(Error::Released)?.2[usize::from(bar)]
            .as_ref()
            .ok_or(Error::InvalidBar)?
            .read32(offset)
            .map_err(|_| Error::Io { bar, offset })
    }
    fn write(&mut self, bar: u8, offset: u64, value: u32) -> Result<(), Error> {
        self.owners.as_mut().ok_or(Error::Released)?.2[usize::from(bar)]
            .as_mut()
            .ok_or(Error::InvalidBar)?
            .write32(offset, value)
            .map_err(|_| Error::Io { bar, offset })?;
        if self.read(bar, offset)? != value {
            return Err(Error::Readback { bar, offset });
        }
        Ok(())
    }
    fn mask_inner(&mut self) -> Result<(), Error> {
        let control = self.checked()?;
        let command = self.owners.as_mut().unwrap().0.config().read16(COMMAND);
        if command == u16::MAX {
            return Err(MsiError::FailedRead { offset: COMMAND }.into());
        }
        self.config_write(COMMAND, command | INTX_DISABLE)?;
        // Linux enables MSI-X under Function Mask before accessing table RAM:
        // some devices do not decode that RAM until MSI-X Enable is set.
        self.config_write(self.layout.offset + 2, control | ENABLE | FUNCTION_MASK)?;
        for vector in 0..self.layout.vectors {
            let offset = self.layout.table_offset + u64::from(vector) * ENTRY_BYTES + 12;
            self.write(self.layout.table_bar, offset, VECTOR_MASK)?;
        }
        Ok(())
    }
    /// Mask all vectors and fallback INTx. No cause/CPU/DMA drain is inferred.
    pub fn mask(&mut self) -> Result<(), Error> {
        let result = self.mask_inner();
        self.fail(result)
    }
    pub fn disable(&mut self) -> Result<(), Error> {
        self.message = None;
        let result = (|| {
            self.mask_inner()?;
            let control = self.checked()?;
            self.config_write(self.layout.offset + 2, (control | FUNCTION_MASK) & !ENABLE)
        })();
        self.fail(result)
    }
    /// Program vector zero; all unused vectors remain individually masked.
    /// # Safety
    /// Message belongs to the actual qualified IRQ registry/route. The source,
    /// old posted messages, callbacks and work have drained before retargeting;
    /// masking alone is insufficient. Keep all actual DMA/IRQ owners retained.
    pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), Error> {
        if message.address & 3 != 0 {
            return Err(Error::InvalidMessage);
        }
        self.message = None;
        let result = (|| {
            self.mask_inner()?;
            let bar = self.layout.table_bar;
            let offset = self.layout.table_offset;
            self.write(bar, offset, message.address as u32)?;
            self.write(bar, offset + 4, (message.address >> 32) as u32)?;
            self.write(bar, offset + 8, message.data)?;
            self.checked()?;
            Ok(())
        })();
        self.fail(result)?;
        self.message = Some(message);
        Ok(())
    }
    /// # Safety
    /// Actual callback/route is installed and published. The requester, all
    /// source/work/reset/DMA owners and real interrupt controller stay retained.
    pub unsafe fn unmask(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Quarantined);
        }
        let message = self.message.ok_or(Error::NotProgrammed)?;
        let result = (|| {
            self.mask_inner()?;
            let bar = self.layout.table_bar;
            let offset = self.layout.table_offset;
            for (part, value) in [
                (0, message.address as u32),
                (4, (message.address >> 32) as u32),
                (8, message.data),
            ] {
                if self.read(bar, offset + part)? != value {
                    return Err(Error::Readback {
                        bar,
                        offset: offset + part,
                    });
                }
            }
            self.write(bar, offset + 12, 0)?;
            let control = self.checked()?;
            self.config_write(self.layout.offset + 2, (control | ENABLE) & !FUNCTION_MASK)
        })();
        self.fail(result)
    }
    /// Return exact owners only after independent real source/IRQ/work drain.
    /// # Safety
    /// Device is stopped; old pending/posted MSI-X writes, callbacks and all
    /// deferred/reset/timer users have drained and cannot restart. DMA lease,
    /// fence, coherency and IOMMU retirement remain independently owned. Mapped
    /// BARs must be explicitly retired by their actual owner after this return.
    pub unsafe fn release(&mut self) -> Result<Owners<C, B>, Error> {
        self.disable()?;
        self.owners.take().ok_or(Error::Released)
    }
}
impl<C: MsiConfigSpace, B: BarAccess> Drop for MsixConfig<C, B> {
    fn drop(&mut self) {
        if let Some(owners) = self.owners.take() {
            core::mem::forget(owners);
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        }
    }
}
pub fn quarantined_configurations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests;
