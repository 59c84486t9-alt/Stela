// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Native access to a kept, mapped PCH register window.
use super::{Fault, Registers};
use alloc::sync::Arc;
use core::ptr::NonNull;

pub struct Mmio {
    base: NonNull<u8>,
    bytes: usize,
    _owner: Arc<dyn core::any::Any>,
}
impl Mmio {
    /// # Safety
    /// The entire range is a live exclusive UC mapping of the PCH MAC
    /// BAR, not a physical-address cast. `owner` keeps its real PCI reservation,
    /// mapping and power through its final Drop. The complete `Registers`
    /// ordering/exclusion/quiescence contract holds; no unrelated token suffices.
    pub unsafe fn from_owned_window(
        base: NonNull<u8>,
        bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Fault> {
        if base.as_ptr() as usize & 3 != 0 {
            return Err(Fault::Misaligned);
        }
        if bytes < 4 || (base.as_ptr() as usize).checked_add(bytes).is_none() {
            return Err(Fault::OutsideBar);
        }
        Ok(Self {
            base,
            bytes,
            _owner: owner,
        })
    }
    fn pointer(&self, at: u32) -> Result<*mut u32, Fault> {
        if at & 3 != 0 {
            return Err(Fault::Misaligned);
        }
        let at = usize::try_from(at).map_err(|_| Fault::OutsideBar)?;
        if at.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(Fault::OutsideBar);
        }
        // SAFETY: the constructor keeps the live mapping, and full aligned
        // bounds were checked before creating this raw pointer.
        Ok(unsafe { self.base.as_ptr().add(at).cast() })
    }
}
// SAFETY: construction requires the real UC/reservation/exclusion grant, which
// remains held; all accesses check complete bounds before volatile use.
unsafe impl Registers for Mmio {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        // SAFETY: pointer validates the entire live aligned u32 access.
        Ok(u32::from_le(unsafe { self.pointer(at)?.read_volatile() }))
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        // SAFETY: pointer validates the entire live aligned u32 access.
        unsafe { self.pointer(at)?.write_volatile(value.to_le()) };
        Ok(())
    }
}

/// Native PCH NVM MAC/flash windows, keeping their single PCI owner.
pub struct NvmMmio {
    mac: Mmio,
    flash: NonNull<u8>,
    flash_bytes: usize,
}
// SAFETY: the NVM window constructors keep the same-function MAC
// mapping and exclude all other users. The composed PCH owner serializes MAC,
// PHY and flash accesses; forwarding does not create another reservation.
unsafe impl Registers for NvmMmio {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        self.mac.read32(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.mac.write32(at, value)
    }
}
impl NvmMmio {
    /// # Safety
    /// These are the exclusive UC MAC and separate flash BAR mappings
    /// of one observed PCH2/LPT function. `owner` keeps both complete mappings,
    /// reservation and power, and the NVM `Registers` contract holds. Neither
    /// pointer may be synthesized from a physical address. There are no other
    /// PHY/NVM/MAC users of this function while these windows are owned.
    pub unsafe fn from_separate_windows(
        mac: NonNull<u8>,
        mac_bytes: usize,
        flash: NonNull<u8>,
        flash_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Fault> {
        // SAFETY: caller supplies the same-function exclusive windows.
        unsafe { Self::windows(mac, mac_bytes, flash, flash_bytes, owner) }
    }
    /// # Safety
    /// `mac` is the complete exclusive UC MAC BAR of the observed SPT+
    /// PCH function. `owner` keeps its real reservation/power/mapping and
    /// excludes every other register user. Its flash registers really occupy
    /// the MAC's +0xe000 subwindow. The NVM `Registers` contract holds.
    pub unsafe fn from_mac_window(
        mac: NonNull<u8>,
        mac_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Fault> {
        if mac_bytes < 0xe000 + 20 || (mac.as_ptr() as usize).checked_add(mac_bytes).is_none() {
            return Err(Fault::OutsideBar);
        }
        // SAFETY: full MAC range was checked and caller keeps it.
        let flash = unsafe { NonNull::new_unchecked(mac.as_ptr().add(0xe000)) };
        // SAFETY: this is the same BAR's checked flash subwindow.
        unsafe { Self::windows(mac, mac_bytes, flash, mac_bytes - 0xe000, owner) }
    }
    unsafe fn windows(
        mac: NonNull<u8>,
        mac_bytes: usize,
        flash: NonNull<u8>,
        flash_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Fault> {
        if flash.as_ptr() as usize & 3 != 0 {
            return Err(Fault::Misaligned);
        }
        if mac_bytes < 0x5b58
            || flash_bytes < 20
            || (flash.as_ptr() as usize).checked_add(flash_bytes).is_none()
        {
            return Err(Fault::OutsideBar);
        }
        // SAFETY: the public constructor supplies the MAC mapping/owner.
        let mac = unsafe { Mmio::from_owned_window(mac, mac_bytes, owner) }?;
        Ok(Self {
            mac,
            flash,
            flash_bytes,
        })
    }
    fn flash_pointer(&self, at: u32, width: usize) -> Result<*mut u8, super::nvm::Error> {
        let at = usize::try_from(at).map_err(|_| super::nvm::Error::Bounds)?;
        if at & (width - 1) != 0
            || at
                .checked_add(width)
                .is_none_or(|end| end > self.flash_bytes)
        {
            return Err(super::nvm::Error::Bounds);
        }
        // SAFETY: constructor keeps complete native window; full aligned
        // access is checked before the pointer is subsequently dereferenced.
        Ok(unsafe { self.flash.as_ptr().add(at) })
    }
}
// SAFETY: both constructors require the same function/UC windows and
// complete serialized NVM grant; all width-specific accesses check full bounds.
unsafe impl super::nvm::Registers for NvmMmio {
    fn read_mac32(&mut self, at: u32) -> Result<u32, super::nvm::Error> {
        self.mac.read32(at).map_err(|_| super::nvm::Error::Access)
    }
    fn read16(&mut self, at: u32) -> Result<u16, super::nvm::Error> {
        // SAFETY: the checked pointer is within the mapping.
        Ok(u16::from_le(unsafe {
            self.flash_pointer(at, 2)?.cast::<u16>().read_volatile()
        }))
    }
    fn read32(&mut self, at: u32) -> Result<u32, super::nvm::Error> {
        // SAFETY: the checked pointer is within the mapping.
        Ok(u32::from_le(unsafe {
            self.flash_pointer(at, 4)?.cast::<u32>().read_volatile()
        }))
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), super::nvm::Error> {
        // SAFETY: the checked pointer is within the mapping.
        unsafe {
            self.flash_pointer(at, 2)?
                .cast::<u16>()
                .write_volatile(value.to_le())
        };
        Ok(())
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), super::nvm::Error> {
        // SAFETY: the checked pointer is within the mapping.
        unsafe {
            self.flash_pointer(at, 4)?
                .cast::<u32>()
                .write_volatile(value.to_le())
        };
        Ok(())
    }
}
