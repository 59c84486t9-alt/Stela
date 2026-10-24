// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig
// Copyright (C) 2026 Stela contributors
//! Owned indexed MSI-X programming for native PCI devices.
//!
//! Layout/programming follows pinned Linux PCI MSI. The actual PCI/config/reset
//! and UC BAR mappings stay retained through failures. Masking is never a DMA,
//! device-cause, callback, posted-write or interrupt-controller drain proof.
use super::{
    Address, EcamConfig, Function,
    msi::{MsiConfigSpace, MsiError, RetainedOwner},
};
use crate::bus::{irq::MsiMessage, mmio::owned::PhysicalSpan};
use alloc::vec::Vec;
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
    InvalidIndex,
    InvalidSelection,
    Allocation,
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

// Hardware bounds this to 2,048 bits. No per-entry message array lives on a
// bounded task stack; this set is also the complete selection scratch space.
#[derive(Clone, Copy, Default)]
struct EntrySet([u64; 32]);
impl EntrySet {
    fn contains(&self, index: u16) -> bool {
        self.0[usize::from(index / 64)] & (1_u64 << (index % 64)) != 0
    }
    fn insert(&mut self, index: u16) {
        self.0[usize::from(index / 64)] |= 1_u64 << (index % 64);
    }
    fn remove(&mut self, index: u16) {
        self.0[usize::from(index / 64)] &= !(1_u64 << (index % 64));
    }
    fn selection(indices: &[u16], vectors: u16) -> Result<Self, Error> {
        if indices.is_empty() || indices.len() > usize::from(vectors) {
            return Err(Error::InvalidSelection);
        }
        let mut set = Self::default();
        for &index in indices {
            if index >= vectors {
                return Err(Error::InvalidIndex);
            }
            if set.contains(index) {
                return Err(Error::InvalidSelection);
            }
            set.insert(index);
        }
        Ok(set)
    }
}

pub type Owners<C, B> = (Function<C>, RetainedOwner, [Option<B>; 6]);

/// Unique function/table owner. Operations and final Drop belong to process or
/// deferred context, including fallible replay-state allocation and its release.
/// Numerical message storage never replaces the caller's retained route owners.
pub struct MsixConfig<C: MsiConfigSpace = EcamConfig, B: BarAccess = MappedBar> {
    owners: Option<Owners<C, B>>,
    layout: Layout,
    // Preserve the old entry-zero no-allocation path. Remaining messages are
    // initialized directly in fallibly reserved heap storage, never on stack.
    message: Option<MsiMessage>,
    messages: Vec<Option<MsiMessage>>,
    live: EntrySet,
    initialized: bool,
    open: bool,
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
                messages: Vec::new(),
                live: EntrySet::default(),
                initialized: false,
                open: false,
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
    fn invalidate_messages(&mut self) {
        self.message = None;
        self.messages.fill(None);
        self.live = EntrySet::default();
    }
    fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.invalidate_messages();
            self.poisoned = true;
        }
        result
    }
    fn entry_offset(&self, index: u16) -> Result<u64, Error> {
        if index >= self.layout.vectors {
            return Err(Error::InvalidIndex);
        }
        let offset = u64::from(index)
            .checked_mul(ENTRY_BYTES)
            .and_then(|bytes| self.layout.table_offset.checked_add(bytes))
            .ok_or(Error::InvalidTable)?;
        let end = offset.checked_add(ENTRY_BYTES).ok_or(Error::InvalidTable)?;
        let table_end = u64::from(self.layout.vectors)
            .checked_mul(ENTRY_BYTES)
            .and_then(|bytes| self.layout.table_offset.checked_add(bytes))
            .ok_or(Error::InvalidTable)?;
        let backing = self.owners.as_ref().ok_or(Error::Released)?.2
            [usize::from(self.layout.table_bar)]
            .as_ref()
            .ok_or(Error::InvalidBar)?;
        if end > table_end || !backing.accessible(offset, ENTRY_BYTES) {
            return Err(Error::Mapping);
        }
        Ok(offset)
    }
    fn reserve_messages(&mut self) -> Result<(), Error> {
        let count = usize::from(self.layout.vectors - 1);
        if self.messages.len() < count {
            // Vec is still empty on a refusal. Once capacity is reserved, each
            // element is initialized in-place without another allocation.
            self.messages
                .try_reserve_exact(count - self.messages.len())
                .map_err(|_| Error::Allocation)?;
            self.messages.resize(count, None);
        }
        Ok(())
    }
    fn message_at(&self, index: u16) -> Option<MsiMessage> {
        if index == 0 {
            self.message
        } else {
            self.messages.get(usize::from(index - 1)).copied().flatten()
        }
    }
    fn set_message(&mut self, index: u16, message: MsiMessage) {
        if index == 0 {
            self.message = Some(message);
        } else {
            self.messages[usize::from(index - 1)] = Some(message);
        }
    }
    fn verify_message(&self, index: u16, message: MsiMessage) -> Result<(), Error> {
        let bar = self.layout.table_bar;
        let offset = self.entry_offset(index)?;
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
        Ok(())
    }
    fn check_owned_control(&self, control: u16) -> Result<(), Error> {
        if self.initialized {
            let expected = ENABLE | if self.open { 0 } else { FUNCTION_MASK };
            if control & (ENABLE | FUNCTION_MASK) != expected {
                return Err(Error::CapabilityChanged);
            }
        }
        Ok(())
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
    fn begin_mask(&mut self, control: u16) -> Result<(), Error> {
        let command = self.owners.as_mut().unwrap().0.config().read16(COMMAND);
        if command == u16::MAX {
            return Err(MsiError::FailedRead { offset: COMMAND }.into());
        }
        self.config_write(COMMAND, command | INTX_DISABLE)?;
        // Linux enables MSI-X under Function Mask before accessing table RAM:
        // some devices do not decode that RAM until MSI-X Enable is set.
        self.config_write(self.layout.offset + 2, control | ENABLE | FUNCTION_MASK)
    }
    fn mask_with(&mut self, control: u16) -> Result<(), Error> {
        self.begin_mask(control)?;
        for vector in 0..self.layout.vectors {
            let offset = self.entry_offset(vector)? + 12;
            self.write(self.layout.table_bar, offset, VECTOR_MASK)?;
        }
        self.live = EntrySet::default();
        self.initialized = true;
        self.open = false;
        Ok(())
    }
    fn mask_inner(&mut self) -> Result<(), Error> {
        let control = self.checked()?;
        self.mask_with(control)
    }
    /// Mask all vectors and fallback INTx. No cause/CPU/DMA drain is inferred.
    pub fn mask(&mut self) -> Result<(), Error> {
        let result = self.mask_inner();
        self.fail(result)
    }
    pub fn disable(&mut self) -> Result<(), Error> {
        self.invalidate_messages();
        let result = (|| {
            self.mask_inner()?;
            let control = self.checked()?;
            self.config_write(self.layout.offset + 2, (control | FUNCTION_MASK) & !ENABLE)
        })();
        self.fail(result)?;
        self.initialized = false;
        self.open = false;
        Ok(())
    }
    // Both APIs share the index/entry core. Legacy mode deliberately preserves
    // the original all-mask trace and discards nonzero replay after success.
    fn program_entry(
        &mut self,
        index: u16,
        message: MsiMessage,
        legacy: bool,
    ) -> Result<(), Error> {
        if message.address & 3 != 0 {
            return Err(Error::InvalidMessage);
        }
        if self.poisoned {
            return Err(Error::Quarantined);
        }
        let offset = match self.entry_offset(index) {
            Ok(offset) => offset,
            Err(error) if legacy => return self.fail(Err(error)),
            Err(error) => return Err(error),
        };
        if index != 0 {
            self.reserve_messages()?;
        }
        let result = (|| {
            let reopen = if legacy || !self.initialized {
                self.mask_inner()?;
                false
            } else {
                let control = self.checked()?;
                self.check_owned_control(control)?;
                self.begin_mask(control)?;
                self.write(self.layout.table_bar, offset + 12, VECTOR_MASK)?;
                self.open
            };
            let bar = self.layout.table_bar;
            self.write(bar, offset, message.address as u32)?;
            self.write(bar, offset + 4, (message.address >> 32) as u32)?;
            self.write(bar, offset + 8, message.data)?;
            self.checked()?;
            if reopen {
                // Other callbacks/routes remain published. A global guard is
                // only a temporary delivery hold, never their retirement.
                for peer in 0..self.layout.vectors {
                    if peer != index && self.live.contains(peer) {
                        let recorded = self.message_at(peer).ok_or(Error::NotProgrammed)?;
                        self.verify_message(peer, recorded)?;
                        let peer_offset = self.entry_offset(peer)? + 12;
                        if self.read(bar, peer_offset)? & VECTOR_MASK != 0 {
                            return Err(Error::Readback { bar, offset: peer_offset });
                        }
                    }
                }
                let control = self.checked()?;
                self.config_write(self.layout.offset + 2, (control | ENABLE) & !FUNCTION_MASK)?;
            }
            Ok(())
        })();
        self.fail(result)?;
        self.set_message(index, message);
        self.live.remove(index);
        if legacy {
            self.messages.fill(None);
        }
        Ok(())
    }
    /// Program vector zero; all unused vectors remain individually masked.
    /// Successful legacy use invalidates all nonzero indexed replay messages.
    /// # Safety
    /// Message belongs to the actual qualified IRQ registry/route for this
    /// function/root epoch, including any real interrupt-remapping authority.
    /// The whole affected source set, old posted messages, callbacks and work
    /// have drained before this legacy all-mask transition. Masking alone is
    /// insufficient. Keep all actual DMA/IRQ owners retained. Process/deferred
    /// context only; this primitive does not validate route authorization.
    pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), Error> {
        self.program_entry(0, message, true)
    }
    /// Program one entry and leave it masked, preserving other live entries.
    /// Entry zero needs no allocation; first nonzero use fallibly reserves all
    /// remaining replay slots before hardware access. Function Mask temporarily
    /// holds peer delivery; peer messages and pending bits remain untouched.
    /// # Safety
    /// Retain the actual uniquely owned function/reset/root and qualified route
    /// for the full message, without guessing remapped-address encodings. The
    /// target's actual source, posted messages, callbacks and work are stopped
    /// and drained before retargeting; other live routes/callbacks stay retained
    /// and published throughout. No concurrent table/config/reset access.
    /// Process/deferred context only; masking never proves retirement.
    pub unsafe fn program_indexed(&mut self, index: u16, message: MsiMessage) -> Result<(), Error> {
        self.program_entry(index, message, false)
    }
    fn unmask_entries(&mut self, indices: &[u16], legacy: bool) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Quarantined);
        }
        let selection = EntrySet::selection(indices, self.layout.vectors)?;
        for &index in indices {
            self.message_at(index).ok_or(Error::NotProgrammed)?;
            self.entry_offset(index)?;
        }
        let result = (|| {
            let control = self.checked()?;
            if !legacy {
                self.check_owned_control(control)?;
            }
            self.mask_with(control)?;
            // Verify EVERY selected message before opening ANY entry.
            for &index in indices {
                let message = self.message_at(index).ok_or(Error::NotProgrammed)?;
                self.verify_message(index, message)?;
            }
            for &index in indices {
                let offset = self.entry_offset(index)?;
                self.write(self.layout.table_bar, offset + 12, 0)?;
            }
            let control = self.checked()?;
            self.config_write(self.layout.offset + 2, (control | ENABLE) & !FUNCTION_MASK)
        })();
        self.fail(result)?;
        self.live = selection;
        self.open = true;
        if legacy {
            self.messages.fill(None);
        }
        Ok(())
    }
    /// Activate only entry zero and invalidate all nonzero replay messages.
    /// # Safety
    /// The actual callback/route is installed and published. Any nonzero live
    /// sources, pending/posted messages, callbacks and work are stopped/drained
    /// before changing to this legacy set. Retain all requester, source/work,
    /// reset/DMA and interrupt-controller owners. Process/deferred context only.
    pub unsafe fn unmask(&mut self) -> Result<(), Error> {
        self.unmask_entries(&[0], true)
    }
    /// Activate exactly this nonempty, unique set of programmed entries together.
    /// All selected messages are verified under Function Mask before any entry
    /// mask is cleared; Function Mask is cleared last. Unselected entries stay
    /// masked. This allocates nothing and never writes device-owned PBA state.
    /// # Safety
    /// Every selected entry has an actual authorized retained route and already
    /// published callback. Removed entries have independently stopped/drained
    /// source, posted messages, CPU pending/inflight callbacks and deferred work.
    /// Retain the real function/reset/root, DMA and interrupt-controller owners;
    /// no concurrent table/config/reset access. Process/deferred context only.
    pub unsafe fn unmask_indices(&mut self, indices: &[u16]) -> Result<(), Error> {
        self.unmask_entries(indices, false)
    }
    /// Return exact owners only after independent real source/IRQ/work drain.
    /// # Safety
    /// Device is stopped across ALL table entries; old pending/posted MSI-X
    /// writes, callbacks and all deferred/reset/timer users have drained and cannot restart. DMA lease,
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
