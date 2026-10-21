// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Realtek copper Ethernet, one polled queue without VLAN/checksum/TSO offloads.
//!
//! Native Rust adaptation of Linux r8169 at
//! `a804c5742bff224d4cb4d25dd383554d598be32b`, including its ordered MAC
//! revision table, analogue PHY sequences and firmware-script instruction set.
//! See `crates/stela-drivers/THIRD_PARTY.md` and `LICENSES/GPL-2.0-only.txt`.
//!
//! This slice implements MAC versions 02..06 (8169S/SB/SC, 8110S/SB/SC),
//! 17..24 (8168B/C/CP, 8111B/C/CP) and 34 (8168E-VL/8111E-VL). PHY IDs
//! `001c:c800` (internal FE/GE) and `001c:c912` (RTL8211B) are accepted only
//! with actual copper-gigabit capabilities. Version 34 requires the exact
//! `rtl_nic/rtl8168e-3.fw` resource. No firmware bytes are embedded or copied.
//!
//! Later 8168/8111, 8125 and 8126 MAC versions are identified for diagnostics
//! but **refused** until their complete MAC/PHY initialization is implemented.
//! RTL8139, 100Mbps-only chips, ancient unsupported version 01, external PHY
//! variants, SFP/TBI, DASH, suspend/resume, interrupts and jumbo frames are
//! outside this slice. This is not a whole-family hardware qualification.
//!
//! DMA buffers live until reboot even on startup/transmit errors. OWN is the
//! sole ownership transfer; timed-out transmit slots are never overwritten.

use super::{Link, LinkError, MAX_FRAME, MIN_FRAME, Mac};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::DmaAllocator,
        mmio::Mmio,
        pci::{self, ConfigSpace, Function},
    },
    firmware as resources, registers as map_registers,
};
use alloc::{format, string::String, vec::Vec};
use core::{
    fmt,
    sync::atomic::{Ordering, fence},
};
mod firmware;
mod hardware;
mod phy;
mod registers;
mod revision;
mod ring;
mod start;
use firmware::Script;
use hardware::Hardware;
use registers::*;
pub use revision::Revision;
use ring::Ring;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Device(BlockError),
    Firmware(resources::Error),
    Script(&'static str),
    UnknownMac(u32),
    UnsupportedRevision(Revision),
    UnsupportedPhy(u32),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(e) => e.fmt(f),
            Self::Firmware(e) => e.fmt(f),
            Self::Script(e) => write!(f, "Realtek firmware/PHY: {e}"),
            Self::UnknownMac(tx) => write!(f, "unknown Realtek MAC TxConfig {tx:#010x}"),
            Self::UnsupportedRevision(r) => write!(
                f,
                "{} MAC version {} XID {:03x} startup is not implemented",
                r.name, r.version, r.xid
            ),
            Self::UnsupportedPhy(id) => write!(
                f,
                "Realtek copper PHY {id:#010x} startup is not implemented"
            ),
        }
    }
}
impl core::error::Error for Error {}
impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Self::Device(e)
    }
}
impl From<resources::Error> for Error {
    fn from(e: resources::Error) -> Self {
        Self::Firmware(e)
    }
}
fn block_error(e: BlockError) -> Error {
    e.into()
}

/// Candidate PCI IDs; the constructor additionally requires an exact supported
/// MAC revision and copper PHY. PCI-ID recognition alone does not claim support.
pub fn matches<C: ConfigSpace>(function: &Function<C>) -> bool {
    function.vendor == 0x10ec
        && matches!(function.device, 0x8161 | 0x8168 | 0x8169 | 0x8125 | 0x8126)
        && function.class == [2, 0, 0]
}
trait Registers {
    fn read8(&self, offset: usize) -> u8;
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn write8(&self, offset: usize, value: u8);
    fn write16(&self, offset: usize, value: u16);
    fn write32(&self, offset: usize, value: u32);
}
impl Registers for Mmio {
    fn read8(&self, o: usize) -> u8 {
        self.read8(o)
    }
    fn read16(&self, o: usize) -> u16 {
        self.read16(o)
    }
    fn read32(&self, o: usize) -> u32 {
        self.read32(o)
    }
    fn write8(&self, o: usize, v: u8) {
        self.write8(o, v)
    }
    fn write16(&self, o: usize, v: u16) {
        self.write16(o, v)
    }
    fn write32(&self, o: usize, v: u32) {
        self.write32(o, v)
    }
}
trait Timer {
    fn now(&self) -> u64;
    fn delay(&self, microseconds: u64);
}
impl Timer for Clock {
    fn now(&self) -> u64 {
        self.now_us()
    }
    fn delay(&self, us: u64) {
        self.delay(us)
    }
}

pub struct Realtek {
    device: Mmio,
    clock: Clock,
    receive: Ring,
    transmit: Ring,
    mac: Mac,
    link_status: Option<u8>,
    revision: Revision,
    pub location: String,
}
impl Realtek {
    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// Initialize one exclusively owned physical function after ExitBootServices.
    /// The provider's exact binding is `driver=realtek`, lowercase PCI identity
    /// (e.g. `10ec:8168`), `revision=xid-2c8`, `board=None`. XID contains every
    /// TxConfig bit used by Linux's version table, even bits its mask ignores.
    /// The image is borrowed only for this call; its allocation is never copied.
    ///
    /// # Safety
    /// Caller exclusively owns the actual controller and its segment's PCI
    /// configuration. Handoff ECAM/MMIO and DMA resources must be actual mapped
    /// uncached/device-accessible machine ranges. Firmware and other drivers
    /// must not access them, including during BAR sizing and upstream ASPM edits.
    pub unsafe fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
        provider: &dyn resources::Provider,
    ) -> Result<Self, Error> {
        if !matches(function) {
            return Err(
                BlockError::Unsupported("not a supported Realtek PCI Ethernet candidate").into(),
            );
        }
        if function.device != 0x8169 {
            // SAFETY: caller grants exclusive PCI segment access and valid ECAM.
            unsafe { pci::disable_aspm_link(function, handoff)? };
            let cap = function
                .capabilities()
                .into_iter()
                .find(|(_, id)| *id == 0x10)
                .ok_or(BlockError::Unsupported(
                    "Realtek PCIe function without PCIe capability",
                ))?
                .0;
            let offset = u16::from(cap) + 0x10;
            let config = function.config();
            config.write16(offset, config.read16(offset) & !(1 << 8)); // Disable CLKREQ as Linux's start branches require.
        }
        let bar = function
            .bars()
            .into_iter()
            .flatten()
            .find(|b| matches!(b, pci::Bar::Memory { .. }));
        let device = map_registers(handoff, bar, 0, 256)?;
        function.enable();
        let txconfig = device.read32(TX_CONFIG);
        let revision = revision::detect(txconfig).ok_or(Error::UnknownMac(txconfig))?;
        if !revision::pci_family(function.device, revision) || !revision.implemented() {
            return Err(Error::UnsupportedRevision(revision));
        }
        if device.read8(PHY_STATUS) & 0x80 != 0 {
            return Err(BlockError::Unsupported("Realtek TBI/fiber mode").into());
        }
        let subsystem = function.config().read32(0x2c);
        let mut hardware =
            Hardware::new(&device, &handoff.clock, revision, function.address.function);
        hardware.reset()?;
        if revision.version <= 6 {
            function.config().write16(0x0c, 0x4008); // Linux cache-line/latency values, narrow config write.
            device.write8(0x82, 1);
        }
        let mac = station(device.read32(MAC0), device.read32(MAC4)).ok_or(
            BlockError::Unsupported("Realtek without a valid station MAC"),
        )?;
        let identity = format!("{:04x}:{:04x}", function.vendor, function.device);
        let image = load_firmware(provider, &identity, revision)?;
        let script = image
            .map(|image| Script::parse(image.bytes()))
            .transpose()?;
        hardware.configure_phy(script.as_ref(), subsystem == 0xe000_1458)?;
        hardware.reset()?; // Linux resets the MAC again after PHY initialization.
        hardware.configure_mac()?;
        // Nothing has a descriptor address yet. Allocation faults cannot start DMA.
        let mut net = Self {
            device,
            clock: handoff.clock,
            receive: Ring::new(dma, revision.version >= 18)?,
            transmit: Ring::new(dma, revision.version >= 18)?,
            mac,
            link_status: None,
            revision,
            location: format!(
                "{} {} XID {:03x}",
                function.address, revision.name, revision.xid
            ),
        };
        net.receive.initialize(true);
        net.transmit.initialize(false);
        let hardware = Hardware::new(&net.device, &net.clock, revision, function.address.function);
        if let Err(error) = publish(&hardware, &net.receive, &net.transmit, mac) {
            // Buffers remain boot-owned even if a disconnected/stuck device fails reset.
            let _ =
                Hardware::new(&net.device, &net.clock, revision, function.address.function).reset();
            return Err(error.into());
        }
        Ok(net)
    }

    fn update_link(&mut self) -> Result<bool, LinkError> {
        let status = self.device.read8(PHY_STATUS);
        if status == u8::MAX {
            return Err(LinkError::Adapter(format!(
                "{} PCI read failed",
                self.location
            )));
        }
        if self.link_status != Some(status) && status & 2 != 0 && self.revision.version == 34 {
            let hardware = Hardware::new(&self.device, &self.clock, self.revision, 0);
            link_patch(&hardware, status).map_err(|e| {
                LinkError::Adapter(format!("{} link configuration: {e}", self.location))
            })?;
        }
        self.link_status = Some(status);
        Ok(status & 2 != 0)
    }
}

fn load_firmware<'a>(
    provider: &'a dyn resources::Provider,
    hardware: &str,
    revision: Revision,
) -> Result<Option<resources::Image<'a>>, Error> {
    let xid = format!("xid-{:03x}", revision.xid);
    revision
        .firmware
        .map(|name| {
            provider
                .load(resources::Requirement {
                    name,
                    target: resources::Target {
                        driver: "realtek",
                        hardware,
                        revision: &xid,
                        board: None,
                    },
                    minimum_bytes: 4,
                })
                .map_err(Error::from)
        })
        .transpose()
}

fn link_patch<R: Registers, T: Timer>(
    hw: &Hardware<'_, R, T>,
    status: u8,
) -> Result<(), BlockError> {
    let (first, second) = match status & 0x1c {
        0x10 => (0x11, 0x05),
        0x08 => (0x1f, 0x05),
        0x04 => (0x1f, 0x3f),
        _ => {
            return Err(BlockError::Unsupported(
                "Realtek link reports an unknown copper speed",
            ));
        }
    };
    hw.eri_write(0x1bc, 15, first)?;
    hw.eri_write(0x1dc, 15, second)?;
    hw.eri_modify(0xdc, 1, 0)?;
    hw.eri_modify(0xdc, 0, 1)
}
fn station(low: u32, high: u32) -> Option<Mac> {
    let a = low.to_le_bytes();
    let b = high.to_le_bytes();
    let mac = Mac([a[0], a[1], a[2], a[3], b[0], b[1]]);
    (!mac.is_multicast() && mac.0 != [0; 6]).then_some(mac)
}
fn publish<R: Registers, T: Timer>(
    hw: &Hardware<'_, R, T>,
    rx: &Ring,
    tx: &Ring,
    mac: Mac,
) -> Result<(), BlockError> {
    let r = hw.registers;
    let revision = hw.revision;
    r.write8(CONFIG_LOCK, 0xc0);
    let result = (|| {
        let low = u32::from_le_bytes(mac.0[..4].try_into().expect("MAC low word"));
        let high = u32::from(u16::from_le_bytes([mac.0[4], mac.0[5]]));
        r.write32(MAC4, high);
        r.read8(COMMAND);
        r.write32(MAC0, low);
        r.read8(COMMAND);
        if revision.version == 34 {
            // Linux rtl_rar_exgmac_set: both EXGMAC address representations,
            // including reserved bytes which may retain stale firmware state.
            hw.eri_write(0xe0, 15, low)?;
            hw.eri_write(0xe4, 15, high)?;
            hw.eri_write(
                0xf0,
                15,
                u32::from(u16::from_le_bytes([mac.0[0], mac.0[1]])) << 16,
            )?;
            hw.eri_write(
                0xf4,
                15,
                u32::from_le_bytes(mac.0[2..].try_into().expect("MAC upper word")),
            )?;
        }
        // Linux requires high-before-low descriptor base writes on some systems.
        r.write32(TX_HIGH, (tx.descriptors.physical() >> 32) as u32);
        r.write32(TX_LOW, tx.descriptors.physical() as u32);
        r.write32(RX_HIGH, (rx.descriptors.physical() >> 32) as u32);
        r.write32(RX_LOW, rx.descriptors.physical() as u32);
        Ok(())
    })();
    r.write8(CONFIG_LOCK, 0);
    result?;
    r.read8(COMMAND);
    fence(Ordering::SeqCst);
    r.write8(COMMAND, ENABLE);
    let rxconfig = if revision.version <= 17 {
        (7 << 13) | (7 << 8)
    } else {
        (1 << 15) | (1 << 14) | (7 << 8)
    };
    // Broadcast, multicast, station only; no promiscuous/errors/runt/VLAN stripping.
    r.write32(RX_CONFIG, rxconfig | 0x0e);
    r.write32(MAR0, u32::MAX);
    r.write32(MAR0 + 4, u32::MAX);
    r.write32(
        TX_CONFIG,
        (7 << 8) | (3 << 24) | if revision.version >= 34 { 1 << 7 } else { 0 },
    );
    r.write16(INTERRUPT_MASK, 0);
    r.write16(INTERRUPT_STATUS, u16::MAX);
    let command = r.read8(COMMAND);
    if command == u8::MAX {
        return Err(BlockError::Device { status: 255 });
    }
    if command & ENABLE != ENABLE {
        return Err(BlockError::Timeout);
    }
    Ok(())
}
impl Link for Realtek {
    fn mac(&self) -> Mac {
        self.mac
    }
    fn carrier(&mut self) -> bool {
        self.update_link().unwrap_or(false)
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(LinkError::Invalid("frame length is outside 14..=1514"));
        }
        self.update_link()?;
        let clock = self.clock;
        if !clock.wait(100_000, || self.transmit.available()) {
            return Err(LinkError::Adapter(format!(
                "{} transmit ring stalled",
                self.location
            )));
        }
        self.transmit.transmit(frame)?;
        fence(Ordering::SeqCst);
        self.device.write8(TX_POLL, POLL_NORMAL);
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.update_link()?;
        Ok(self.receive.receive())
    }
}

#[cfg(test)]
mod tests;
