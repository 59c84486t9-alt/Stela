// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2001-2004 David S. Miller
// Copyright (C) 2001-2003 Jeff Garzik
// Copyright (C) 2004 Sun Microsystems Inc.
// Copyright (C) 2005-2018 Broadcom
//! Broadcom Tigon3 hardware transport for the named BCM5720/5761/5762 cohort.
//!
//! `Packet::attach` composes one polled BCM5720/5761/5762 A0 unmanaged copper
//! queue with requester-domain DMA and explicit retirement. BCM5761 requires
//! function-zero NIC wiring and recognized NVM; its original CLKREQ setting
//! selects the source per-speed send-BD workaround. These
//! bounded source-reviewed packet profiles have native model qualification;
//! hardware remains unqualified. See `tg3/THIRD_PARTY.md`. Managed, SerDes and
//! all other ASIC/revision profiles explicitly refuse.
//!
//! All named chips have an APE window. MDIO takes the actual per-function APE
//! PHY grant, even when management firmware is not running. Linux's ignored
//! lock failures, firmware timeout fallback and silent stop timeout are
//! deliberately errors here. An uncertain operation poisons and retains the
//! actual register owner, never permitting a new epoch by object reconstruction.
mod filter;
mod geometry;
pub use filter::ReceiveFilter;
pub mod io;
mod transport;

pub use packet::Packet;
pub use transport::Hardware;
mod packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access,
    Clock,
    Removed,
    Bounds,
    UnsupportedDevice,
    UnsupportedRevision,
    UnsupportedMedia,
    ApeTimeout,
    MdioTimeout,
    MdioReadFailed,
    FirmwareTimeout,
    StopTimeout(u32),
    UnsupportedManaged,
    UnmanagedNotObserved,
    UnsupportedPcie,
    ConfigDidNotLatch,
    NvramTimeout,
    Poisoned,
    NotIdentified,
    Stopped,
    PhyResetTimeout,
    UnsupportedBoard,
    InvalidMac,
    RingCorrupt,
    Attention {
        flow: u32,
        message: u32,
        read_dma: u32,
        write_dma: u32,
    },
    RingFull,
    Dma(crate::bus::dma::mapping::DmaError),
    Memory(crate::bus::dma::memory::MemoryError),
}

/// Actual serialized PCI/MAC/APE register ownership.
///
/// # Safety
/// Implementors retain one real exclusively reserved PCI function, its actual
/// configuration mapping, and its UC MAC BAR0 and APE BAR2 mappings. Reads and
/// writes are ordered native little-endian device accesses with complete bounds
/// checks and errors on removal. Config writes use actual required widths;
/// there are no other firmware/SMM/driver/IRQ users. MMIO must remain powered
/// and mapped until the owner is explicitly retired. A caller-supplied identity,
/// address cast, unrelated retention token or mock cannot grant native authority.
pub unsafe trait Registers {
    fn function_number(&self) -> u8;
    fn config_read32(&mut self, at: u16) -> Result<u32, Error>;
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error>;
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error>;
    fn read32(&mut self, at: u32) -> Result<u32, Error>;
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error>;
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error>;
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error>;
}

/// Original calibrated timing retained in the device's qualified context.
/// The shared timer checks unavailable rates and uses modular elapsed ticks;
/// its successful waits preserve the complete requested minimum duration.
pub use crate::bus::pci::power::Timer as Delay;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asic {
    Bcm5761,
    Bcm5720,
    Bcm5762,
}

/// Source PCI table membership is only a probe candidate, never an attach grant.
pub fn candidate(vendor: u16, device: u16, class: [u8; 3]) -> bool {
    vendor == 0x14e4
        && class == [2, 0, 0]
        && matches!(device, 0x165f | 0x1680 | 0x1681 | 0x1688 | 0x1689 | 0x1687)
}

impl From<crate::bus::dma::mapping::DmaError> for Error {
    fn from(error: crate::bus::dma::mapping::DmaError) -> Self {
        Self::Dma(error)
    }
}
impl From<crate::bus::dma::memory::MemoryError> for Error {
    fn from(error: crate::bus::dma::memory::MemoryError) -> Self {
        Self::Memory(error)
    }
}
