// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
// Generic PHY link sampling from Linux phy_device.c (GPL-2.0-or-later):
// Copyright (c) 2004 Freescale Semiconductor, Inc.
// Author: Andy Fleming
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
//! 17..26 (8168B/C/CP/D, 8111B/C/CP/D), 28/31 (8168DP/8111DP), 32..36 (8168E/E-VL/F,
//! 8111E/E-VL/F), 38 (RTL8411), 40/42 (8168G/8111G), 44 (RTL8411B) and
//! 46 (8168H/8111H and 8168M), 51 (8168EP/8111EP) and 52 (8168FP/8117).
//! PHY IDs `001c:c800` (internal FE/GE) and `001c:c912` (RTL8211B) are accepted only
//! with actual copper-gigabit capabilities. Versions 25/26 require their exact
//! `rtl_nic/rtl8168d-1.fw`/`rtl_nic/rtl8168d-2.fw` resource and matching PHY
//! firmware-readiness sentinel; 34 requires `rtl_nic/rtl8168e-3.fw`.
//! Versions 32/33/35/36/38/40/42/44/46 require exact revision firmware and the
//! internal FE/GE PHY; external PHY initialization is outside these new paths.
//! E1/E2 return an observable warning: optional EEE cleanup is not performed
//! and EEE advertisement state is unverified. External `.fw` image bytes are
//! never embedded or copied.
//!
//! MAC40/42/44 use checked PHY/MAC OCP, explicit shared FIFO ownership, and
//! their exact PHY/start paths; MAC44 retains the donor's licensed RX fix.
//! MAC46 adds real ADC-bias calibration and saw-count timer programming;
//! EEE advertisement and MAC TX-LPI are cleared, including on link-up.
//! MAC51/52 use the exact EP/FP OOB ERI namespace and bounded CMAC ownership.
//! MAC52 XID54a requires MAC-only `rtl_nic/rtl8168fp-3.fw` after MAC tuning;
//! XID54b and MAC51 require none. Their PHY/EPHY/start paths stay distinct.
//! MAC61/63/64/65 (RTL8125A/B/D/K/9151A/CP) require a checked BAR through 0x604a, their exact
//! revision firmware, a validated internal NBASE PHY and real 2.5G
//! capability. Their distinct FIFO/IRQ/doorbell/RX/EPHY and legacy descriptor
//! setup precede DMA. Carrier uses actual polled PHY BMCR/BMSR with a 10 ms
//! cache; EEE is disabled and 2.5G advertising is capped to the MAC capability.
//! MAC28/31 use the DP MDIO gate and bounded initial DASH driver-start
//! notification/acknowledgement. Their integrated RTL8211B identity erratum
//! is an observable classification correction; MDIO returns actual values.
//! Failed DP command ports require reset/reinitialization, without retries.
//! Later 8125 and 8126 MAC versions are identified for diagnostics
//! but **refused** until their complete MAC/PHY initialization is implemented.
//! RTL8139, 100Mbps-only chips, ancient unsupported version 01, external PHY
//! variants, SFP/TBI, DASH stop/release and power lifecycle, suspend/resume,
//! interrupts and jumbo frames are
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
const NBASE_LINK_POLL_US: u64 = 10_000;

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

/// A tolerated, observable limitation of otherwise completed initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// MAC32/33's optional donor EEE cleanup has no C45 bus implementation.
    /// The optional cleanup is not performed; EEE advertisement is unverified.
    EeeAdvertisementDisableUnavailable,
    /// Exact MAC28/31 integrated RTL8211B reports the generic FE/GE ID.
    /// The raw register read remains available; only driver classification changes.
    DpPhyIdentityCorrected { reported: u32, selected: u32 },
}
impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DpPhyIdentityCorrected { reported, selected } => write!(f,
                "RTL8168DP PHY identity erratum: reported {reported:08x}, selected {selected:08x} RTL8211B initialization"),
            Self::EeeAdvertisementDisableUnavailable => f.write_str(
                "optional EEE advertisement cleanup not performed: C45 access unsupported; EEE advertisement state unverified",
            ),
        }
    }
}

pub struct Realtek {
    device: Mmio,
    clock: Clock,
    receive: Ring,
    transmit: Ring,
    mac: Mac,
    link: RuntimeLink,
    revision: Revision,
    warning: Option<Warning>,
    pub location: String,
}
impl Realtek {
    pub fn warning(&self) -> Option<Warning> {
        self.warning
    }

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
        let pcie_link_control = if function.device != 0x8169 {
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
            clock_request(function.config(), offset, false)?;
            Some(offset)
        } else {
            None
        };
        let bar = function
            .bars()
            .into_iter()
            .flatten()
            .find(|b| matches!(b, pci::Bar::Memory { .. }));
        let device = map_registers(handoff, bar, 0, register_aperture(function.device))?;
        function.enable_polled();
        let txconfig = device.read32(TX_CONFIG);
        let revision = revision::detect(txconfig).ok_or(Error::UnknownMac(txconfig))?;
        if !revision::pci_family(function.device, revision) || !revision.implemented() {
            return Err(Error::UnsupportedRevision(revision));
        }
        if !revision.nbase() && device.read8(PHY_STATUS) & 0x80 != 0 {
            return Err(BlockError::Unsupported("Realtek TBI/fiber mode").into());
        }
        let subsystem = function.config().read32(0x2c);
        let mut hardware =
            Hardware::new(&device, &handoff.clock, revision, function.address.function);
        if revision.nbase() && hardware.mac_ocp_read(0xd006)? & 0xff == 7 {
            return Err(BlockError::Unsupported("Realtek SFP mode").into());
        }
        hardware.initialize_modern()?;
        hardware.reset()?;
        hardware.dp_start()?;
        hardware.ep_start()?;
        if revision.version <= 6 {
            function.config().write16(0x0c, 0x4008); // Linux cache-line/latency values, narrow config write.
            device.write8(0x82, 1);
        }
        let mac = read_station(&hardware)?;
        let identity = format!("{:04x}:{:04x}", function.vendor, function.device);
        let image = load_firmware(provider, &identity, revision)?;
        let script = image
            .map(|image| Script::parse(image.bytes()))
            .transpose()?;
        let warning = hardware.configure_phy(script.as_ref(), subsystem == 0xe000_1458)?;
        hardware.reset()?; // Linux resets the MAC again after PHY initialization.
        hardware.configure_mac(script.as_ref())?;
        if revision.version == 28 {
            // The exact DP4 start branch enables CLKREQ after EPHY setup.
            // ASPM link states remain disabled by the shared PCI boundary.
            let offset = pcie_link_control.ok_or(BlockError::Unsupported(
                "Realtek DP without PCIe link control",
            ))?;
            clock_request(function.config(), offset, true)?;
        }
        // Nothing has a descriptor address yet. Allocation faults cannot start DMA.
        let mut net = Self {
            device,
            clock: handoff.clock,
            receive: Ring::new(dma, revision.version >= 18)?,
            transmit: Ring::new(dma, revision.version >= 18)?,
            mac,
            link: RuntimeLink::default(),
            revision,
            warning,
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
        let hardware = Hardware::new(&self.device, &self.clock, self.revision, 0);
        self.link.update(&hardware).map_err(|error| {
            LinkError::Adapter(format!("{} link configuration: {error}", self.location))
        })
    }
}

/// Link-programming errors leave command completion and filter state uncertain.
/// There is no retry or in-place recovery: only a fresh constructor after the
/// caller's explicit device reset/reinitialization can regain ownership.
#[derive(Default)]
struct RuntimeLink {
    status: Option<u8>,
    failure: Option<BlockError>,
    last_phy_poll: Option<u64>,
}
impl RuntimeLink {
    fn update<R: Registers, T: Timer>(
        &mut self,
        hw: &Hardware<'_, R, T>,
    ) -> Result<bool, BlockError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if hw.revision.nbase()
            && self
                .last_phy_poll
                .is_some_and(|last| hw.timer.now().wrapping_sub(last) < NBASE_LINK_POLL_US)
        {
            return Ok(self.status.is_some_and(|status| status & 2 != 0));
        }
        let observed: Result<u8, BlockError> = if hw.revision.nbase() {
            // genphy_update_link's polled BMCR/BMSR sequence preserves a
            // latch-low drop while up, and retries a low sample while down.
            // A 10 ms cache keeps PHY polling out of the per-packet fast path.
            (|| {
                let read = |reg| {
                    let value = hw.phy_read(reg)?;
                    if value == u16::MAX {
                        Err(BlockError::Device { status: 65535 })
                    } else {
                        Ok(value)
                    }
                };
                if read(PHY_CONTROL)? & (1 << 9) != 0 {
                    return Ok(0);
                }
                let previous_up = self.status.is_some_and(|status| status & 2 != 0);
                let mut status = read(1)?;
                if !previous_up && status & 4 == 0 {
                    status = read(1)?;
                }
                // This driver always configures autonegotiation: an old
                // link indication must not outlive a cleared AN-complete bit.
                Ok(if status & (4 | (1 << 5)) == 4 | (1 << 5) {
                    2
                } else {
                    0
                })
            })()
        } else {
            Ok(hw.registers.read8(PHY_STATUS))
        };
        let status = match observed {
            Ok(status) => status,
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };
        let result = if status == u8::MAX {
            Err(BlockError::Device { status: 255 })
        } else if self.status != Some(status)
            && status & 2 != 0
            && matches!(hw.revision.version, 34..=36 | 38 | 46 | 51 | 52 | 61 | 63..=65)
        {
            link_patch(hw, status)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            self.failure = Some(error.clone());
            return Err(error);
        }
        self.status = Some(status);
        if hw.revision.nbase() {
            self.last_phy_poll = Some(hw.timer.now());
        }
        Ok(status & 2 != 0)
    }
}

fn clock_request<C: ConfigSpace>(
    config: &mut C,
    link_control: u16,
    enabled: bool,
) -> Result<(), BlockError> {
    let value = config.read16(link_control);
    if value == u16::MAX {
        return Err(BlockError::Device {
            status: u32::from(value),
        });
    }
    config.write16(
        link_control,
        (value & !(1 << 8)) | (u16::from(enabled) << 8),
    );
    Ok(())
}

fn register_aperture(device: u16) -> u64 {
    if matches!(device, 0x8125 | 0x8126) {
        NBASE_REGISTER_BYTES
    } else {
        256
    }
}

fn kick_transmit(registers: &impl Registers, revision: Revision) {
    if revision.nbase() {
        registers.write16(NBASE_TX_POLL, 1);
    } else {
        registers.write8(TX_POLL, POLL_NORMAL);
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
    if hw.revision.nbase() {
        hw.mac_ocp_modify(0xe040, 3, 0)?;
        if hw.revision.version == 61 {
            hw.mac_ocp_modify(0xeb62, 6, 0)?;
        }
        return Ok(());
    }
    if matches!(hw.revision.version, 46 | 51 | 52) {
        // EEE stays disabled, including stale MAC TX-LPI state at link-up.
        hw.registers.write8(0x1b, hw.mmio8(0x1b)? & !7);
        return hw.eri_modify(0x1b0, 3, 0);
    }
    let (first, mut second) = match status & 0x1c {
        0x10 => (0x11, 0x05),
        0x08 => (0x1f, 0x05),
        0x04 => (0x1f, 0x3f),
        _ => {
            return Err(BlockError::Unsupported(
                "Realtek link reports an unknown copper speed",
            ));
        }
    };
    if matches!(hw.revision.version, 35 | 36) && status & 0x1c != 0x10 {
        second = 0x3f;
    }
    hw.eri_write(0x1bc, 15, first)?;
    hw.eri_write(0x1dc, 15, second)?;
    if matches!(hw.revision.version, 34 | 38) {
        hw.eri_modify(0xdc, 1, 0)?;
        hw.eri_modify(0xdc, 0, 1)?;
    }
    Ok(())
}
fn read_station<R: Registers, T: Timer>(hw: &Hardware<'_, R, T>) -> Result<Mac, BlockError> {
    if hw.revision.nbase()
        && let Some(mac) = station(
            hw.mmio32(NBASE_MAC0_BACKUP)?,
            hw.mmio32(NBASE_MAC0_BACKUP + 4)?,
        )
    {
        return Ok(mac);
    }
    if matches!(
        hw.revision.version,
        35 | 36 | 38 | 40 | 42 | 44 | 46 | 51 | 52
    ) && let Some(mac) = station(hw.eri_read(0xe0)?, hw.eri_read(0xe4)?)
    {
        return Ok(mac);
    }
    station(hw.registers.read32(MAC0), hw.registers.read32(MAC4)).ok_or(BlockError::Unsupported(
        "Realtek without a valid station MAC",
    ))
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
    let rxconfig = match revision.version {
        2..=17 => (7 << 13) | (7 << 8),
        25 | 26 | 28 | 31 | 32 | 33 => (1 << 15) | (7 << 8),
        40 | 42 | 44 | 46 | 51 | 52 => (1 << 15) | (1 << 14) | (7 << 8) | (1 << 11),
        61 => (8 << 27) | (7 << 8),
        63..=65 => (8 << 27) | (7 << 8) | (1 << 11),
        _ => (1 << 15) | (1 << 14) | (7 << 8),
    };
    // Broadcast, multicast, station only; no promiscuous/errors/runt/VLAN stripping.
    r.write32(RX_CONFIG, rxconfig | 0x0e);
    r.write32(MAR0, u32::MAX);
    r.write32(MAR0 + 4, u32::MAX);
    r.write32(
        TX_CONFIG,
        (7 << 8)
            | (3 << 24)
            | if (34..=52).contains(&revision.version) {
                1 << 7
            } else {
                0
            },
    );
    hw.interrupts_off();
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
        kick_transmit(&self.device, self.revision);
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.update_link()?;
        Ok(self.receive.receive())
    }
}

#[cfg(test)]
mod tests {
    // SPDX-License-Identifier: GPL-2.0-only
    // Copyright (c) 2026 Stela contributors
    //! Stateful protocol model, with delayed command completion and real DMA rings
    //! tested separately. The revision/analogue expectations are from the pinned
    //! Linux sources; this is not a physical-device or RTL8139 emulator claim.
    use super::*;
    use alloc::{collections::BTreeMap, rc::Rc};
    use core::cell::{Cell, RefCell};

    #[derive(Clone, Default)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now(&self) -> u64 {
            self.0.get()
        }
        fn delay(&self, us: u64) {
            self.0.set(self.0.get() + us)
        }
    }
    #[derive(Default)]
    struct State {
        bytes: Vec<u8>,
        phy: BTreeMap<(u16, u16), u16>,
        ephy: [u16; 32],
        eri: BTreeMap<u16, u32>,
        oob: BTreeMap<u16, u32>,
        ep_ready_at: Option<u64>,
        cmac_ready_at: Option<u64>,
        mac: BTreeMap<u16, u16>,
        phy_ocp: BTreeMap<u16, u16>,
        dp_ocp: BTreeMap<u16, u32>,
        dp_ready_at: Option<(u64, u16)>,
        dp_commands: usize,
        g_parameter: u16,
        g_parameters: BTreeMap<u16, u16>,
        n_parameter: u16,
        n_parameters: BTreeMap<u16, u16>,
        bmsr_latch_low_once: bool,
        page: u16,
        parameter: u16,
        parameters: BTreeMap<u16, u16>,
        efuse: u8,
        extended_page: u16,
        extended: BTreeMap<(u16, u16), u16>,
        pending: Option<(usize, u32, u64)>,
        reset_phy_at: Option<u64>,
        reset_mac_at: Option<u64>,
        shared_ready_at: Option<u64>,
        writes: Vec<(usize, u32, u8)>,
        mdio_commands: usize,
        phy_ocp_commands: usize,
        eri_commands: usize,
    }
    struct Model {
        state: RefCell<State>,
        time: Time,
        fault: Option<usize>,
        failed_read: Option<usize>,
        fail_phy_at: usize,
        fail_eri_at: usize,
        stuck_reset: bool,
        stuck_phy_reset: bool,
        command_readback: Option<u8>,
        shared_ready_delay: Option<u64>,
        dp_mode: bool,
        dp_ready_delay: Option<u64>,
        fail_dp_at: usize,
        h_adc: Option<(u16, u16)>,
        ep_mode: Option<u8>,
        ep_ready_delay: Option<u64>,
        cmac_ready_delay: Option<u64>,
        fail_mac_address: Option<u16>,
        internal_nbase: bool,
        fail_phy_ocp_at: usize,
    }
    impl Model {
        fn ready(time: &Time) -> Self {
            let mut state = State {
                bytes: vec![0; 256],
                ..State::default()
            };
            for (reg, value) in [
                (0, 0x1140),
                (1, 0x7909),
                (2, 0x001c),
                (3, 0xc800),
                (9, 0x1b00),
                (15, 0x3000),
            ] {
                state.phy.insert((0, reg), value);
            }
            Self {
                state: RefCell::new(state),
                time: time.clone(),
                fault: None,
                failed_read: None,
                fail_phy_at: usize::MAX,
                fail_eri_at: usize::MAX,
                stuck_reset: false,
                stuck_phy_reset: false,
                command_readback: None,
                shared_ready_delay: None,
                dp_mode: false,
                dp_ready_delay: Some(20_000),
                fail_dp_at: usize::MAX,
                h_adc: None,
                ep_mode: None,
                ep_ready_delay: Some(20_000),
                cmac_ready_delay: Some(75_000),
                fail_mac_address: None,
                internal_nbase: false,
                fail_phy_ocp_at: usize::MAX,
            }
        }
        fn dp(time: &Time, version: u8, dash: bool) -> Self {
            let mut model = Self::ready(time);
            model.dp_mode = true;
            {
                let mut s = model.state.borrow_mut();
                Self::store32(&mut s, DP_MDIO_GATE, DP_MDIO_GATED);
                s.dp_ocp.insert(
                    if version == 31 { 0xb8 } else { 0x10 },
                    if dash { 1 << 15 } else { 0 },
                );
            }
            model
        }
        fn modern(time: &Time) -> Self {
            let mut model = Self::ready(time);
            model.shared_ready_delay = Some(300);
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.extend([
                    (0xa400, 0x1940),
                    (0xa402, 0x7909),
                    (0xa404, 0x001c),
                    (0xa406, 0xc800),
                    (0xa412, 0x1b00),
                    (0xa41e, 0x3000),
                    (0xa616, 0),
                ]);
                s.bytes[MCU] = 0x32;
                Self::store32(&mut s, TX_CONFIG, 1 << 11);
                s.eri.insert(0xe0, 0x0504_0302);
                s.eri.insert(0xe4, 0x0706);
            }
            model
        }
        fn ep(time: &Time, version: u8, dash: bool) -> Self {
            let mut model = Self::modern(time);
            model.ep_mode = Some(version);
            {
                let mut s = model.state.borrow_mut();
                s.bytes[IBCR0] = 0x85;
                s.bytes[IBCR2] = 0x85;
                s.oob.insert(0x128, u32::from(dash));
            }
            model
        }
        fn nbase(time: &Time) -> Self {
            let mut model = Self::modern(time);
            model.internal_nbase = true;
            {
                let mut s = model.state.borrow_mut();
                s.bytes.resize(0x7000, 0);
                s.bytes[INTERRUPT_MITIGATION..INTERRUPT_MITIGATION + 2]
                    .copy_from_slice(&0x0103u16.to_le_bytes());
                s.phy_ocp.insert(0xa616, 0x2070);
                Self::store32(&mut s, NBASE_MAC0_BACKUP, 0x0504_0302);
                Self::store32(&mut s, NBASE_MAC0_BACKUP + 4, 0x0706);
            }
            model
        }
        fn raw32(s: &State, o: usize) -> u32 {
            u32::from_le_bytes(s.bytes[o..o + 4].try_into().unwrap())
        }
        fn store32(s: &mut State, o: usize, v: u32) {
            s.bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn complete(&self, s: &mut State) {
            if s.ep_ready_at.is_some_and(|at| self.time.now() >= at) {
                *s.oob.entry(0x124).or_default() |= 1;
                s.ep_ready_at = None;
            }
            if s.cmac_ready_at.is_some_and(|at| self.time.now() >= at) {
                s.bytes[IBISR0] |= 0x20;
                s.cmac_ready_at = None;
            }
            if let Some((at, reg)) = s.dp_ready_at
                && self.time.now() >= at
            {
                *s.dp_ocp.entry(reg).or_default() |= 1 << 11;
                s.dp_ready_at = None;
            }
            if s.shared_ready_at.is_some_and(|at| self.time.now() >= at) {
                s.bytes[MCU] |= 2;
                s.shared_ready_at = None;
            }
            if s.reset_phy_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_phy_reset {
                s.phy.entry((0, 0)).and_modify(|v| *v &= !PHY_RESET);
                s.phy_ocp
                    .entry(OCP_PHY_BASE)
                    .and_modify(|v| *v &= !PHY_RESET);
                s.reset_phy_at = None;
            }
            if s.reset_mac_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_reset {
                s.bytes[COMMAND] &= !RESET;
                s.reset_mac_at = None;
            }
            let Some((port, command, when)) = s.pending else {
                return;
            };
            if self.time.now() < when
                || self.fault == Some(port)
                || (port == PHY_ACCESS && s.mdio_commands >= self.fail_phy_at)
                || (port == ERI_ADDRESS && s.eri_commands >= self.fail_eri_at)
                || (port == DP_OCP_ACCESS && s.dp_commands >= self.fail_dp_at)
                || (port == PHY_OCP && s.phy_ocp_commands >= self.fail_phy_ocp_at)
            {
                return;
            }
            s.pending = None;
            let write = command & ACCESS != 0;
            let value = match port {
                PHY_ACCESS => {
                    let reg = ((command >> 16) & 31) as u16;
                    if write {
                        if reg == PHY_PAGE {
                            s.page = command as u16;
                        } else {
                            s.phy.insert((s.page, reg), command as u16);
                            if s.page == 5 && reg == 5 {
                                s.parameter = command as u16;
                            } else if s.page == 5 && reg == 6 {
                                s.parameters.insert(s.parameter, command as u16);
                            }
                            if s.page == 7 {
                                if reg == 0x1e {
                                    s.extended_page = command as u16;
                                } else {
                                    s.extended.insert((s.extended_page, reg), command as u16);
                                }
                            }
                            if s.page == 0 && reg == 0 && command as u16 & PHY_RESET != 0 {
                                s.reset_phy_at = Some(self.time.now() + 100);
                            }
                        }
                        command & !ACCESS
                    } else {
                        let value = if reg == PHY_PAGE {
                            s.page
                        } else if s.page == 5 && reg == 6 {
                            *s.parameters.get(&s.parameter).unwrap_or(&0)
                        } else if s.page == 7 && reg != 0x1e {
                            *s.extended.get(&(s.extended_page, reg)).unwrap_or(&0)
                        } else {
                            *s.phy.get(&(s.page, reg)).unwrap_or(&0)
                        };
                        (command & !0xffff) | ACCESS | u32::from(value)
                    }
                }
                EFUSE_ACCESS => command | ACCESS | u32::from(s.efuse),
                EPHY_ACCESS => {
                    let reg = ((command >> 16) & 31) as usize;
                    if write {
                        s.ephy[reg] = command as u16;
                        command & !ACCESS
                    } else {
                        command | ACCESS | u32::from(s.ephy[reg])
                    }
                }
                ERI_ADDRESS => {
                    let reg = (command & 0xfff) as u16;
                    let oob = command & 0x30000 == 0x20000;
                    if oob {
                        assert_eq!(
                            command & 0x7ffc_0000,
                            if self.ep_mode == Some(52) {
                                0x3dc0_0000
                            } else {
                                0
                            }
                        );
                    }
                    if write {
                        let mut value =
                            *(if oob { &s.oob } else { &s.eri }).get(&reg).unwrap_or(&0);
                        let data = Self::raw32(s, ERI_DATA);
                        for byte in 0..4 {
                            if command & (1 << (12 + byte)) != 0 {
                                value =
                                    (value & !(0xff << (byte * 8))) | (data & (0xff << (byte * 8)));
                            }
                        }
                        if oob {
                            s.oob.insert(reg, value);
                            if reg == 0x30
                                && value & 1 != 0
                                && s.oob.get(&0x180).is_some_and(|v| *v & 0xff == 5)
                                && s.oob[&0x128] & 1 != 0
                            {
                                s.ep_ready_at =
                                    self.ep_ready_delay.map(|delay| self.time.now() + delay);
                            }
                        } else {
                            s.eri.insert(reg, value);
                        }
                        command & !ACCESS
                    } else {
                        Self::store32(
                            s,
                            ERI_DATA,
                            *(if oob { &s.oob } else { &s.eri }).get(&reg).unwrap_or(&0),
                        );
                        command | ACCESS
                    }
                }
                CSI_ADDRESS => {
                    // The source helper preserves the other config bytes at 70c.
                    if !write {
                        Self::store32(s, CSI_DATA, 0x1278_5634);
                    }
                    if write {
                        command & !ACCESS
                    } else {
                        command | ACCESS
                    }
                }
                DP_OCP_ACCESS => {
                    let address = (command & 0xfff) as u16;
                    if write {
                        let data = Self::raw32(s, DP_OCP_DATA);
                        let mut value = *s.dp_ocp.get(&address).unwrap_or(&0);
                        for byte in 0..4 {
                            if command & (1 << (12 + byte)) != 0 {
                                let mask = 0xff << (8 * byte);
                                value = (value & !mask) | (data & mask);
                            }
                        }
                        s.dp_ocp.insert(address, value);
                        if address == 0x30 && data == 1 {
                            let reg = if s.dp_ocp.contains_key(&0xb8) {
                                0xb8
                            } else {
                                0x10
                            };
                            if s.eri[&0xe8] & 0xff == 5 && s.dp_ocp[&reg] & (1 << 15) != 0 {
                                s.dp_ready_at = self
                                    .dp_ready_delay
                                    .map(|delay| (self.time.now() + delay, reg));
                            }
                        }
                        command & !ACCESS
                    } else {
                        Self::store32(s, DP_OCP_DATA, *s.dp_ocp.get(&address).unwrap_or(&0));
                        command | ACCESS
                    }
                }
                PHY_OCP => {
                    // Address bit0 is always zero. Data bit15 occupies the
                    // same command bit15 and must not contaminate the address.
                    let address = ((command >> 15) as u16) & !1;
                    if write {
                        // Pinned realtek_main.c: internal NBASE C22 MMD
                        // access has no effect and its data reads always zero.
                        // The driver uses it only to detect internal versus
                        // external MMD access, never to claim a successful MMD write.
                        if !(self.internal_nbase && matches!(address, 0xa41a | 0xa41c)) {
                            s.phy_ocp.insert(address, command as u16);
                        }
                        if address == 0xa436 {
                            s.g_parameter = command as u16;
                        } else if address == 0xa438 {
                            s.g_parameters.insert(s.g_parameter, command as u16);
                        } else if address == 0xb87c {
                            s.n_parameter = command as u16;
                        } else if address == 0xb87e {
                            s.n_parameters.insert(s.n_parameter, command as u16);
                        }
                        if address == OCP_PHY_BASE && command as u16 & PHY_RESET != 0 {
                            s.reset_phy_at = Some(self.time.now() + 100);
                        }
                        command & !ACCESS
                    } else {
                        let value = if address == 0xa402 && s.bmsr_latch_low_once {
                            s.bmsr_latch_low_once = false;
                            *s.phy_ocp.get(&address).unwrap_or(&0) & !4
                        } else if self.internal_nbase && address == 0xa41c {
                            0
                        } else if address == 0xb87e {
                            *s.n_parameters.get(&s.n_parameter).unwrap_or(&0)
                        } else if address == 0xa438 {
                            *s.g_parameters.get(&s.g_parameter).unwrap_or(&0)
                        } else {
                            *s.phy_ocp.get(&address).unwrap_or(&0)
                        };
                        command | ACCESS | u32::from(value)
                    }
                }
                _ => panic!("unmodeled command port"),
            };
            Self::store32(s, port, value);
        }
    }
    impl Registers for Model {
        fn read8(&self, o: usize) -> u8 {
            if self.failed_read == Some(o) {
                return u8::MAX;
            }
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            if o == COMMAND
                && self.fail_mac_address.is_some_and(|address| {
                    s.writes
                        .iter()
                        .rfind(|(r, _, _)| *r == MAC_OCP)
                        .is_some_and(|(_, v, _)| {
                            *v & ACCESS != 0 && (*v >> 15) as u16 & !1 == address
                        })
                })
            {
                return u8::MAX;
            }
            if o == COMMAND && s.bytes[o] == ENABLE {
                return self.command_readback.unwrap_or(s.bytes[o]);
            }
            s.bytes[o]
        }
        fn read16(&self, o: usize) -> u16 {
            if self.failed_read == Some(o) {
                return u16::MAX;
            }
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            u16::from_le_bytes(s.bytes[o..o + 2].try_into().unwrap())
        }
        fn read32(&self, o: usize) -> u32 {
            if self.failed_read == Some(o) {
                return u32::MAX;
            }
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            Self::raw32(&s, o)
        }
        fn write8(&self, o: usize, v: u8) {
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            s.writes.push((o, u32::from(v), 1));
            if self.ep_mode.is_some() && o == IBISR0 {
                s.bytes[o] &= !v; // W1C management status.
                return;
            }
            s.bytes[o] = v;
            if self.ep_mode.is_some() && o == IBCR2 && v & 1 == 0 {
                s.cmac_ready_at = self.cmac_ready_delay.map(|delay| self.time.now() + delay);
            }
            if o == COMMAND && v & RESET != 0 {
                s.reset_mac_at = Some(self.time.now() + 300);
            }
        }
        fn write16(&self, o: usize, v: u16) {
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            s.writes.push((o, u32::from(v), 2));
            s.bytes[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn write32(&self, o: usize, v: u32) {
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            s.writes.push((o, v, 4));
            if matches!(
                o,
                PHY_ACCESS
                    | EPHY_ACCESS
                    | ERI_ADDRESS
                    | CSI_ADDRESS
                    | PHY_OCP
                    | EFUSE_ACCESS
                    | DP_OCP_ACCESS
            ) {
                if o == PHY_ACCESS {
                    if self.dp_mode {
                        assert_eq!(Model::raw32(&s, DP_MDIO_GATE) & DP_MDIO_GATED, 0);
                    }
                    s.mdio_commands += 1;
                } else if o == ERI_ADDRESS {
                    s.eri_commands += 1;
                } else if o == DP_OCP_ACCESS {
                    s.dp_commands += 1;
                } else if o == PHY_OCP {
                    s.phy_ocp_commands += 1;
                }
                s.pending = Some((o, v, self.time.now() + 15));
            }
            if o == MAC_OCP && !self.dp_mode {
                let reg = (((v & !ACCESS) >> 15) as u16) & !1;
                if v & ACCESS != 0 {
                    s.mac.insert(reg, v as u16);
                    if reg == 0xe8de || (self.internal_nbase && reg == 0xc01e) {
                        s.bytes[MCU] &= !2;
                        s.shared_ready_at =
                            self.shared_ready_delay.map(|delay| self.time.now() + delay);
                    }
                } else {
                    let data = u32::from(match (self.h_adc, reg) {
                        (Some((a, _)), 0xdd02) => a,
                        (Some((_, b)), 0xdd00) => b,
                        _ => *s.mac.get(&reg).unwrap_or(&0),
                    });
                    Self::store32(&mut s, o, data);
                    return;
                }
            }
            Self::store32(&mut s, o, v);
        }
    }
    fn revision(version: u8) -> Revision {
        let xid = match version {
            2 => 0x008,
            3 => 0x040,
            4 => 0x100,
            5 => 0x180,
            6 => 0x980,
            17 => 0x380,
            18 => 0x3c8,
            19 => 0x3c0,
            20 => 0x3c2,
            21 => 0x3c3,
            22 => 0x3c4,
            23 => 0x3c9,
            24 => 0x3ca,
            25 => 0x281,
            26 => 0x280,
            28 => 0x28a,
            31 => 0x28b,
            46 => 0x541,
            51 => 0x502,
            52 => 0x54a,
            61 => 0x609,
            63 => 0x641,
            64 => 0x688,
            65 => 0x708,
            32 => 0x2c1,
            33 => 0x2c0,
            35 => 0x480,
            36 => 0x481,
            38 => 0x488,
            40 => 0x4c0,
            42 => 0x509,
            44 => 0x5c8,
            34 => 0x2c8,
            _ => panic!("fixture revision"),
        };
        revision::detect(xid << 20).unwrap()
    }
    #[test]
    fn exact_ordered_revision_fixtures_refuse_unknown_ancient_and_wrong_pci_family() {
        // Independent source-table cases include overlapping specific/generic masks.
        for (xid, version, fw) in [
            (0x3c8, 18, None),
            (0x3c9, 23, None),
            (0x3ca, 24, None),
            (0x3c0, 19, None),
            (0x3c2, 20, None),
            (0x3c3, 21, None),
            (0x3c4, 22, None),
            (0x281, 25, Some("rtl_nic/rtl8168d-1.fw")),
            (0x280, 26, Some("rtl_nic/rtl8168d-2.fw")),
            (0x2c1, 32, Some("rtl_nic/rtl8168e-1.fw")),
            (0x2c0, 33, Some("rtl_nic/rtl8168e-2.fw")),
            (0x2c8, 34, Some("rtl_nic/rtl8168e-3.fw")),
            (0x641, 63, Some("rtl_nic/rtl8125b-2.fw")),
            (0x609, 61, Some("rtl_nic/rtl8125a-3.fw")),
            (0x688, 64, Some("rtl_nic/rtl8125d-1.fw")),
            (0x689, 64, Some("rtl_nic/rtl8125d-2.fw")),
            (0x68a, 64, Some("rtl_nic/rtl8125k-1.fw")),
            (0x68b, 64, Some("rtl_nic/rtl9151a-1.fw")),
            (0x708, 65, Some("rtl_nic/rtl8125cp-1.fw")),
            (0x649, 70, Some("rtl_nic/rtl8126a-2.fw")),
            (0x64a, 70, Some("rtl_nic/rtl8126a-3.fw")),
            (0x980, 6, None),
        ] {
            let r = revision::detect(xid << 20).unwrap();
            assert_eq!((r.version, r.firmware), (version, fw));
            assert_eq!(u32::from(r.xid), xid);
            if version >= 61 && !matches!(version, 61 | 63..=65) {
                assert!(!r.implemented());
            }
        }
        for xid in [0u32, 0x300, 0x7c8, 0x6c9, 0xfcf] {
            assert!(revision::detect(xid << 20).is_none());
        }
        assert!(revision::detect(u32::MAX).is_none());
        assert!(revision::pci_family(0x8169, revision(2)));
        assert!(!revision::pci_family(0x8168, revision(2)));
        assert!(!revision::pci_family(0x8125, revision(34)));
    }
    #[test]
    fn every_implemented_phy_branch_executes_analogue_sequence_and_restarts_copper_aneg() {
        for version in [2, 3, 4, 5, 6, 17, 18, 19, 20, 21, 22, 23, 24, 34] {
            let time = Time::default();
            let model = Model::ready(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            let bytes = 0x801f_0000u32.to_le_bytes();
            let script = Script::parse(&bytes).unwrap();
            hw.configure_phy(Some(&script), version == 5).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.page, 0, "version{version}");
            assert_eq!(s.phy[&(0, 4)], 0x1e1);
            assert_eq!(s.phy[&(0, 9)] & 0xfb00, 0x0200);
            assert_eq!(s.phy[&(0, 0)], 0x1200);
            let expected = match version {
                2 | 3 => ((1, 0x18), 0x65c7),
                4 => ((2, 1), 0x90d0),
                5 => ((1, 0x10), 0xf01b),
                6 => ((1, 0x18), 0x67c7),
                17 => ((1, 0x10), 0xf41b),
                18 => ((2, 0xc), 0x1ec8),
                19 => ((3, 0x12), 0xc096),
                20 => ((2, 6), 0x0761),
                21 | 22 => ((2, 6), 0x5461),
                23 | 24 => ((1, 0x1d), 0x3d98),
                34 => ((3, 9), 0xa20f),
                _ => unreachable!(),
            };
            assert_eq!(s.phy[&expected.0], expected.1, "version{version}");
            assert!(time.now() >= 70_000);
            assert!(
                s.writes
                    .iter()
                    .all(|(o, v, _)| *o != COMMAND || *v != u32::from(ENABLE))
            );
        }
    }
    #[test]
    fn exact_phy_id_and_capability_validation_has_no_synthetic_success() {
        for (reg, value) in [(2, 0xffff), (3, 0xc910), (1, 0), (15, 0)] {
            let time = Time::default();
            let model = Model::ready(&time);
            model.state.borrow_mut().phy.insert((0, reg), value);
            let mut hw = Hardware::new(&model, &time, revision(18), 0);
            assert!(hw.configure_phy(None, false).is_err());
            assert!(!model.state.borrow().phy.contains_key(&(2, 0x0c)));
        }
    }
    #[test]
    fn reset_mdio_ephy_eri_csi_faults_are_bounded_and_configuration_lock_restores() {
        for port in [PHY_ACCESS, EPHY_ACCESS, ERI_ADDRESS, CSI_ADDRESS] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.fault = Some(port);
            let mut hw = Hardware::new(&model, &time, revision(34), 3);
            let result = match port {
                PHY_ACCESS => hw.phy_read(2).map(|_| ()),
                EPHY_ACCESS => hw.ephy(1, 0, 1),
                ERI_ADDRESS => hw.eri_read(0xe0).map(|_| ()),
                CSI_ADDRESS => hw.latency(),
                _ => unreachable!(),
            };
            assert_eq!(result, Err(BlockError::Timeout));
            assert!(time.now() <= 10_000);
            if port != PHY_ACCESS {
                assert_eq!(
                    hw.configure_mac(None),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_eq!(model.read8(CONFIG_LOCK), 0);
            }
        }
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.stuck_reset = true;
        let hw = Hardware::new(&model, &time, revision(2), 0);
        assert_eq!(hw.reset(), Err(BlockError::Timeout));
        assert_eq!(time.now(), 10_000);
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.stuck_phy_reset = true;
        let hw = Hardware::new(&model, &time, revision(18), 0);
        assert_eq!(hw.phy_reset(), Err(BlockError::Timeout));
        assert!(time.now() < 700_000);
        // Fail partway through an analogue sequence, not only at its first ID read.
        for nth in [8, 14, 25] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.fail_phy_at = nth;
            let mut hw = Hardware::new(&model, &time, revision(19), 0);
            assert!(hw.configure_phy(None, false).is_err());
            assert!(time.now() < 100_000);
        }
    }
    #[test]
    fn each_mac_revision_uses_its_real_ephy_and_fifo_configuration_before_dma() {
        for version in [2, 3, 4, 5, 6, 17, 18, 19, 20, 21, 22, 23, 24, 34] {
            let time = Time::default();
            let model = Model::ready(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 2);
            hw.reset().unwrap();
            hw.configure_mac(None).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert_eq!(
                u16::from_le_bytes(s.bytes[CPLUS..CPLUS + 2].try_into().unwrap())
                    & ((1 << 5) | (1 << 6)),
                0
            );
            assert!(
                !s.writes
                    .iter()
                    .any(|(reg, _, _)| matches!(*reg, TX_LOW | TX_HIGH | RX_LOW | RX_HIGH))
            );
            match version {
                18 => {
                    assert_eq!(s.ephy[2], 0x1000);
                    assert_eq!(s.ephy[7], 0x2000);
                }
                19 => {
                    assert_eq!(s.ephy[3], 2);
                    assert_eq!(s.bytes[DEBUG], 0x1e);
                }
                20 | 21 => assert_eq!(s.ephy[3], 0x20),
                24 => assert_eq!(s.bytes[DEBUG], 0x20),
                34 => {
                    assert_eq!(s.ephy[0xc], 0x0200);
                    assert_eq!(s.eri[&0xc8], 0x0010_0002);
                    assert_eq!(s.eri[&0xe8], 0x0010_0006);
                    assert_eq!(s.eri[&0xd0], 0x07ff_0060);
                }
                _ => (),
            }
            if version >= 18 {
                let writes: Vec<_> = s
                    .writes
                    .iter()
                    .filter(|(reg, _, _)| *reg == CSI_ADDRESS)
                    .collect();
                assert_eq!(writes[0].1, 0x0002_f70c);
                assert_eq!(writes[1].1, 0x8002_f70c);
                assert!(s.writes.contains(&(CSI_DATA, 0x2778_5634, 4)));
            }
        }
    }
    #[test]
    fn register_validation_rejects_bad_addresses_without_io_and_mac_mcu_page_is_restored() {
        use firmware::ScriptIo;
        let time = Time::default();
        let model = Model::ready(&time);
        let mut hw = Hardware::new(&model, &time, revision(34), 0);
        assert!(hw.phy_read(32).is_err());
        assert!(hw.eri_read(1).is_err());
        assert!(hw.eri_write(0, 0, 0).is_err());
        assert!(hw.ephy(32, 0, 0).is_err());
        assert!(model.state.borrow().writes.is_empty());
        hw.write(true, 31, 0x0a00).unwrap();
        hw.write(true, 0x10, 0x55aa).unwrap();
        assert_eq!(hw.read(true, 0x10).unwrap(), 0x55aa);
        hw.restore();
        hw.write(true, 0, 0x1234).unwrap();
        assert_eq!(model.state.borrow().mac[&OCP_PHY_BASE], 0x1234);
    }
    #[test]
    fn descriptor_publication_is_high_before_low_and_own_before_enable() {
        use crate::bus::dma::RegionAllocator;
        let mut backing = vec![0u64; 40_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(18), 0);
        publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
        let s = model.state.borrow();
        let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
        assert!(at(TX_HIGH) < at(TX_LOW));
        assert!(at(RX_HIGH) < at(RX_LOW));
        assert!(at(RX_LOW) < at(COMMAND));
        for n in 0..DESCRIPTORS {
            assert_eq!(rx.descriptors.read::<u32>(n * DESCRIPTOR) & OWN, OWN);
        }
        drop(s);
        assert_eq!(model.read32(RX_CONFIG) & 0x3f, 0xe);
        assert_eq!(model.read16(INTERRUPT_MASK), 0);
    }
    #[test]
    fn station_mac_rejects_multicast_zero_and_broadcast() {
        assert_eq!(station(0, 0), None);
        assert_eq!(station(1, 0), None);
        assert_eq!(station(u32::MAX, u32::MAX), None);
        assert_eq!(station(0x0504_0302, 0x0706), Some(Mac([2, 3, 4, 5, 6, 7])));
    }

    #[test]
    fn generic_phy_identical_id_nbase_variant_is_refused_before_analogue_programming() {
        let time = Time::default();
        let model = Model::ready(&time);
        model.state.borrow_mut().phy.insert((0xa61, 0x13), 0x2000);
        let mut hw = Hardware::new(&model, &time, revision(18), 0);
        assert_eq!(
            hw.configure_phy(None, false),
            Err(Error::UnsupportedPhy(0x001cc800))
        );
        assert_eq!(model.state.borrow().page, 0);
        assert!(!model.state.borrow().phy.contains_key(&(2, 0xc)));
    }
    #[test]
    fn firmware_catalog_binding_requires_exact_pci_xid_board_and_filename() {
        use resources::{Catalog, ErrorKind, Provenance, Resource, Target};
        let bytes = 0x801f0000u32.to_le_bytes().to_vec();
        // Fixed SHA-256 fixture; identity tests do not derive their expected digest
        // through the same Catalog validation implementation.
        let catalog_digest = [
            0x23, 0xc3, 0xcf, 0xd9, 0x9c, 0xa0, 0x28, 0xa0, 0xba, 0x72, 0xe8, 0x92, 0x40, 0xe4,
            0xb4, 0xf8, 0x93, 0xc1, 0xb4, 0x26, 0xa2, 0x1a, 0x6e, 0x89, 0x36, 0xfd, 0x43, 0x13,
            0x6b, 0x13, 0xc1, 0xba,
        ];
        let catalog = Catalog::from_handoff(vec![Resource {
            name: "rtl_nic/rtl8168e-3.fw",
            target: Target {
                driver: "realtek",
                hardware: "10ec:8168",
                revision: "xid-2c8",
                board: None,
            },
            provenance: Provenance {
                source: "synthetic-test",
                revision: "1",
                member: "rtl_nic/rtl8168e-3.fw",
                license: "MIT",
            },
            expected_length: 4,
            expected_sha256: catalog_digest,
            bytes,
        }])
        .unwrap();
        let image = load_firmware(&catalog, "10ec:8168", revision(34))
            .unwrap()
            .unwrap();
        assert_eq!(image.bytes(), &0x801f0000u32.to_le_bytes());
        assert!(matches!(
            load_firmware(&catalog, "10ec:8161", revision(34)),
            Err(Error::Firmware(resources::Error {
                kind: ErrorKind::WrongTarget,
                ..
            }))
        ));
        let mut other = revision(34);
        other.xid = 0x2c9;
        assert!(load_firmware(&catalog, "10ec:8168", other).is_err());
        assert!(
            load_firmware(&catalog, "10ec:8168", revision(18))
                .unwrap()
                .is_none()
        );
        other.firmware = Some("rtl_nic/rtl8168e-2.fw");
        assert!(matches!(
            load_firmware(&catalog, "10ec:8168", other),
            Err(Error::Firmware(resources::Error {
                kind: ErrorKind::Missing,
                ..
            }))
        ));
    }
    #[test]
    fn link_speed_patch_uses_each_copper_speed_and_rejects_unknown_and_bus_faults() {
        for (speed, first, second) in [(0x10, 0x11, 5), (8, 0x1f, 5), (4, 0x1f, 0x3f)] {
            let time = Time::default();
            let model = Model::ready(&time);
            let hw = Hardware::new(&model, &time, revision(34), 0);
            link_patch(&hw, speed | 2).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.eri[&0x1bc], first);
            assert_eq!(s.eri[&0x1dc], second);
            assert_eq!(s.eri[&0xdc] & 1, 1);
        }
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(34), 0);
        assert!(link_patch(&hw, 2).is_err());
        assert!(model.state.borrow().writes.is_empty());
        let mut model = Model::ready(&time);
        model.fault = Some(ERI_ADDRESS);
        let hw = Hardware::new(&model, &time, revision(34), 0);
        assert_eq!(link_patch(&hw, 0x12), Err(BlockError::Timeout));
    }

    #[test]
    fn mac34_station_replaces_stale_exgmac_before_dma_and_relocks_on_failure() {
        use crate::bus::dma::RegionAllocator;
        for fault in [false, true] {
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all descriptor use and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.state.borrow_mut().eri.extend([
                (0xe0, u32::MAX),
                (0xe4, u32::MAX),
                (0xf0, u32::MAX),
                (0xf4, u32::MAX),
            ]);
            if fault {
                model.fault = Some(ERI_ADDRESS);
            }
            let hw = Hardware::new(&model, &time, revision(34), 0);
            let result = publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7]));
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
            assert!(at(MAC4) < at(MAC0));
            assert!(at(MAC0) < at(ERI_ADDRESS));
            if fault {
                assert_eq!(result, Err(BlockError::Timeout));
                assert!(
                    !s.writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        TX_HIGH | TX_LOW | RX_HIGH | RX_LOW | COMMAND
                    ))
                );
            } else {
                assert_eq!(result, Ok(()));
                assert_eq!(s.eri[&0xe0], 0x0504_0302);
                assert_eq!(s.eri[&0xe4], 0x0000_0706);
                assert_eq!(s.eri[&0xf0], 0x0302_0000);
                assert_eq!(s.eri[&0xf4], 0x0706_0504);
                let eri: Vec<_> = s
                    .writes
                    .iter()
                    .enumerate()
                    .filter(|(_, (r, _, _))| *r == ERI_ADDRESS)
                    .map(|(i, (_, value, _))| (i, *value))
                    .collect();
                assert_eq!(
                    eri.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
                    [0x8000_f0e0, 0x8000_f0e4, 0x8000_f0f0, 0x8000_f0f4]
                );
                assert!(eri.last().unwrap().0 < at(TX_HIGH));
                assert!(at(RX_LOW) < at(COMMAND));
            }
        }
    }

    #[test]
    fn dma_enable_readback_rejects_failed_bus_reads_and_missing_enable_bits() {
        use crate::bus::dma::RegionAllocator;
        for (command, expected) in [
            (u8::MAX, Err(BlockError::Device { status: 255 })),
            (0, Err(BlockError::Timeout)),
            (ENABLE, Ok(())),
        ] {
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all descriptor use and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.command_readback = Some(command);
            let hw = Hardware::new(&model, &time, revision(18), 0);
            assert_eq!(publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])), expected);
        }
    }

    #[test]
    fn rtl8211b_resume_clears_its_suspend_quirk_before_powerup_and_propagates_failure() {
        for (id, fail) in [(0xc912, false), (0xc912, true), (0xc800, false)] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                s.phy.insert((0, 3), id);
                s.phy.insert((0, 14), 0x0200);
                s.phy.insert((0, PHY_CONTROL), 0x1940);
            }
            if fail {
                // Page zero, ID high, ID low, then the RTL8211B quirk write.
                model.fail_phy_at = 4;
            }
            let mut hw = Hardware::new(&model, &time, revision(18), 0);
            let result = hw.configure_phy(None, false);
            let s = model.state.borrow();
            let writes: Vec<_> = s
                .writes
                .iter()
                .filter(|(r, v, _)| *r == PHY_ACCESS && *v & ACCESS != 0)
                .map(|(_, v, _)| (((v >> 16) & 31) as u16, *v as u16))
                .collect();
            if fail {
                assert_eq!(result, Err(Error::Device(BlockError::Timeout)));
                assert_eq!(s.phy[&(0, 14)], 0x0200);
                assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1940);
                assert!(!s.phy.contains_key(&(2, 0x0c)));
                assert_eq!(writes, [(PHY_PAGE, 0), (14, 0)]);
            } else {
                assert_eq!(result, Ok(None));
                if id == 0xc912 {
                    assert_eq!(s.phy[&(0, 14)], 0);
                    let at = |entry| writes.iter().position(|v| *v == entry).unwrap();
                    assert!(at((14, 0)) < at((PHY_CONTROL, 0x1140)));
                    assert!(at((PHY_CONTROL, 0x1140)) < at((0x1d, 0x0f00)));
                    assert!(at((0x1d, 0x0f00)) < at((PHY_CONTROL, 0x9140)));
                    assert!(at((PHY_CONTROL, 0x9140)) < at((PHY_CONTROL, 0x1200)));
                } else {
                    assert_eq!(s.phy[&(0, 14)], 0x0200);
                    assert!(!writes.iter().any(|(reg, _)| *reg == 14));
                }
                assert_eq!(s.phy[&(0, PHY_CONTROL)], 0x1200);
            }
        }
    }

    #[test]
    fn d_revisions_apply_exact_efuse_tuning_and_firmware_only_after_readiness() {
        for (version, sentinel) in [(25, 0xbf00), (26, 0xb300)] {
            for efuse in [0xb1, 0] {
                for low in [0x006c, 0x0070] {
                    let time = Time::default();
                    let model = Model::ready(&time);
                    {
                        let mut s = model.state.borrow_mut();
                        s.efuse = efuse;
                        s.parameters.insert(0x001b, sentinel);
                        s.phy.insert((2, 0x0d), 0x5000 | low);
                        s.phy.insert((2, 2), 0xffff);
                        s.phy.insert((2, 3), 0xffff);
                        s.phy.insert((2, 0x0b), 0xffff);
                        s.phy.insert((2, 0x0c), 0xffff);
                    }
                    // Independent script writes a distinctive page-zero marker.
                    let bytes = 0x8016_a55au32.to_le_bytes();
                    let script = Script::parse(&bytes).unwrap();
                    let mut hw = Hardware::new(&model, &time, revision(version), 0);
                    hw.configure_phy(Some(&script), false).unwrap();
                    let s = model.state.borrow();
                    assert_eq!(s.page, 0);
                    assert_eq!(s.phy[&(1, 6)], 0x4064);
                    assert_eq!(s.phy[&(3, 0x12)], 0xf49f);
                    assert_eq!(s.parameters[&0x8332], 0x5561);
                    let tune = if efuse == 0xb1 {
                        0x669a
                    } else if version == 25 {
                        0x6662
                    } else {
                        0x2642
                    };
                    assert_eq!(s.phy[&(2, 5)], tune);
                    assert_eq!(s.parameters[&0x8330], tune);
                    assert_eq!(s.phy[&(2, 2)], 0xf9ff);
                    assert_eq!(s.phy[&(2, 3)], 0x1fff);
                    if version == 25 {
                        assert_eq!(s.phy[&(2, 0x0b)], 0xff10);
                        assert_eq!(s.phy[&(2, 0x0c)], 0xa2ff);
                        assert_eq!(s.phy[&(2, 0x0f)] & 0x10, 0x10);
                    } else {
                        assert_eq!(s.phy[&(2, 0x0b)], 0xffff);
                        assert_eq!(s.phy[&(2, 0x0c)], 0xffff);
                        assert_eq!(s.phy[&(2, 0x0f)] & 0x17, 0x17);
                    }
                    assert_eq!(s.phy[&(0, 0x16)], 0xa55a);
                    assert_eq!(s.phy[&(0, 0)], 0x1200);
                    let ramp: Vec<_> = s
                        .writes
                        .iter()
                        .filter(|(r, v, _)| *r == PHY_ACCESS && *v & 0xffff_ff00 == 0x800d_5000)
                        .map(|(_, v, _)| *v as u16)
                        .collect();
                    if efuse == 0xb1 && low != 0x6c {
                        assert!(ramp.starts_with(&[
                            0x5065, 0x5066, 0x5067, 0x5068, 0x5069, 0x506a, 0x506b, 0x506c
                        ]));
                    } else {
                        assert!(!ramp.contains(&0x5065));
                    }
                }
            }
        }
    }

    #[test]
    fn d_revisions_refuse_unready_phy_missing_firmware_and_efuse_faults() {
        for version in [25, 26] {
            let bytes = 0x8016_a55au32.to_le_bytes();
            let script = Script::parse(&bytes).unwrap();
            for fault in [false, true] {
                let time = Time::default();
                let mut model = Model::ready(&time);
                if fault {
                    model.fault = Some(EFUSE_ACCESS);
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                let error = hw.configure_phy(Some(&script), false).unwrap_err();
                if fault {
                    assert_eq!(error, Error::Device(BlockError::Timeout));
                } else {
                    assert_eq!(
                        error,
                        Error::Script("RTL8168D PHY is not ready for firmware")
                    );
                }
                let s = model.state.borrow();
                assert_eq!(s.page, 0);
                assert!(!s.phy.contains_key(&(0, 0x16)));
                assert_ne!(s.phy[&(0, 0)], 0x1200);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, v, _)| *r == COMMAND && *v == u32::from(ENABLE))
                );
            }
            let time = Time::default();
            let model = Model::ready(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::Script("RTL8168D requires firmware"))
            );
        }
        let time = Time::default();
        let model = Model::ready(&time);
        let hw = Hardware::new(&model, &time, revision(25), 0);
        assert!(hw.efuse_read(0x400).is_err());
        assert!(model.state.borrow().writes.is_empty());
    }

    #[test]
    fn d_mac_start_clears_stale_jumbo_state_and_uses_single_fetch_receive_configuration() {
        use crate::bus::dma::RegionAllocator;
        for version in [25, 26] {
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all descriptor use and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            let time = Time::default();
            let model = Model::ready(&time);
            model.state.borrow_mut().bytes[CONFIG3] = 0xff;
            model.state.borrow_mut().bytes[CONFIG4] = 0xff;
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_mac(None).unwrap();
            assert_eq!(model.read8(CONFIG3) & 4, 0);
            assert_eq!(model.read8(CONFIG4) & 2, 0);
            assert_eq!(model.read8(CONFIG_LOCK), 0);
            publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
            assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
        }
        for xid in [0x681, 0x649, 0x64a] {
            assert!(!revision::detect(xid << 20).unwrap().implemented());
        }
    }
    #[test]
    fn d_revision_mdio_and_failed_efuse_reads_propagate_for_each_accepted_phy() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for (version, sentinel) in [(25, 0xbf00), (26, 0xb300)] {
            for id in [0xc800, 0xc912] {
                for nth in [20, 45, 70] {
                    let time = Time::default();
                    let mut model = Model::ready(&time);
                    {
                        let mut s = model.state.borrow_mut();
                        s.phy.insert((0, 3), id);
                        s.parameters.insert(0x001b, sentinel);
                        s.efuse = 0xb1;
                    }
                    model.fail_phy_at = nth;
                    let mut hw = Hardware::new(&model, &time, revision(version), 0);
                    assert_eq!(
                        hw.configure_phy(Some(&script), false),
                        Err(Error::Device(BlockError::Timeout))
                    );
                    assert_ne!(model.state.borrow().phy[&(0, 0)], 0x1200);
                }
            }
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.failed_read = Some(EFUSE_ACCESS);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Err(Error::Device(BlockError::Device { status: u32::MAX }))
            );
            assert_eq!(model.state.borrow().page, 0);
        }
    }
    #[test]
    fn f_phy_sequences_preserve_distinct_green_tuning_masks_and_refuse_external_phy() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [35, 36, 38] {
            let time = Time::default();
            let model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                for parameter in [
                    0x8b54, 0x8b55, 0x8b5d, 0x8b5e, 0x8b67, 0x8b70, 0x8b79, 0x8b80, 0x8b85, 0x8b86,
                    0x8a7c, 0x8a7f, 0x8a82, 0x8a85, 0x8a88,
                ] {
                    s.parameters.insert(parameter, 0xffff);
                }
                s.extended.insert((0x20, 0x15), 0xffff);
                s.extended.insert((0x2d, 0x18), 0x8000);
                s.phy.insert((2, 8), 0xffff);
                s.phy.insert((3, 0x19), 0xffff);
                s.phy.insert((3, 0x10), 0xffff);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_phy(Some(&script), false).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.page, 0);
            assert_eq!(s.phy[&(0, 0)], 0x1200);
            assert_eq!(s.phy[&(0, 0x16)], 0xa55a);
            assert_eq!(s.extended[&(0x2d, 0x18)], 0x8010);
            if version != 36 {
                assert_eq!(s.parameters[&0x8b55], 0);
                assert_eq!(s.parameters[&0x8b79], 0xaa00);
                assert_eq!(
                    s.extended[&(0x78, 0x19)],
                    if version == 35 { 0xfb } else { 0xaa }
                );
                assert_eq!(s.phy[&(3, 9)], 0xa20f);
            } else {
                assert_eq!(s.parameters[&0x8b55], 0xffff);
                assert!(!s.extended.contains_key(&(0x78, 0x19)));
            }
            if version == 38 {
                assert_eq!(s.parameters[&0x8b54], 0xf7ff);
                assert_eq!(s.parameters[&0x8a7c], 0xfeff);
                assert_eq!(s.parameters[&0x8a88], 0xfeff);
                assert_eq!(s.phy[&(3, 0x19)], 0xfffe);
                assert_eq!(s.phy[&(3, 0x10)], 0xfbff);
            }
            drop(s);
            let model = Model::ready(&time);
            model.state.borrow_mut().phy.insert((0, 3), 0xc912);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Err(Error::UnsupportedPhy(0x001c_c912))
            );
            assert!(!model.state.borrow().phy.contains_key(&(0, 0x16)));
        }
    }

    #[test]
    fn f_mac_starts_use_distinct_ephy_fifo_and_l1_sequences() {
        for version in [35, 36, 38] {
            let time = Time::default();
            let model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xffff);
                s.bytes[CONFIG3] = 0xff;
                s.bytes[CONFIG4] = 0xff;
                s.bytes[CONFIG5] = 0xff;
                s.bytes[0x1b] = 0xff;
                s.eri.insert(0x1b0, 0xffff);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_mac(None).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert_eq!(s.bytes[CONFIG5] & 9, 0);
            assert_eq!(s.eri[&0xc8], 0x0010_0002);
            assert_eq!(s.eri[&0xd0], 0x60);
            assert_eq!(s.eri[&0x1d0] & 0x12, 0x12);
            assert_eq!(s.eri[&0x1b0] & 3, 0);
            assert_eq!(s.ephy[6], 0xff3f);
            assert_eq!(s.bytes[EARLY_TX], 0x27);
            if version == 38 {
                assert_eq!(s.eri[&0xd4], 0x0c00);
                assert_eq!(s.ephy[0xf], 0x5200);
                assert_eq!(s.bytes[CONFIG3] & 2, 0);
                assert_eq!(s.bytes[0x1b], 0xff);
            } else {
                assert_eq!(s.eri[&0xd4], 0x1f00);
                assert_eq!(s.ephy[8], 0xfffe);
                assert_eq!(s.bytes[0x1b] & 7, 0);
            }
        }
    }

    #[test]
    fn f_station_prefers_eri_with_validity_fallback_and_propagates_access_errors() {
        for version in [35, 36, 38] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                s.eri.insert(0xe0, 0x0504_0302);
                s.eri.insert(0xe4, 0x0706);
                Model::store32(&mut s, MAC0, 0x1514_1312);
                Model::store32(&mut s, MAC4, 0x1716);
            }
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(read_station(&hw).unwrap(), Mac([2, 3, 4, 5, 6, 7]));
            model.state.borrow_mut().eri.insert(0xe0, 0);
            model.state.borrow_mut().eri.insert(0xe4, 0);
            assert_eq!(
                read_station(&hw).unwrap(),
                Mac([0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
            );
            model.fault = Some(ERI_ADDRESS);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(read_station(&hw), Err(BlockError::Timeout));
        }
    }

    #[test]
    fn f_and_8411_link_patches_have_distinct_100m_values_and_filter_reset_rules() {
        for version in [35, 36, 38] {
            for speed in [0x10, 8, 4] {
                let time = Time::default();
                let model = Model::ready(&time);
                let hw = Hardware::new(&model, &time, revision(version), 0);
                link_patch(&hw, speed | 2).unwrap();
                let s = model.state.borrow();
                assert_eq!(s.eri[&0x1bc], if speed == 0x10 { 0x11 } else { 0x1f });
                assert_eq!(
                    s.eri[&0x1dc],
                    if speed == 0x10 || (version == 38 && speed == 8) {
                        5
                    } else {
                        0x3f
                    }
                );
                assert_eq!(s.eri.contains_key(&0xdc), version == 38);
            }
        }
    }
    #[test]
    fn f_required_firmware_mdio_and_mac_protocol_faults_remain_explicit() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [35, 36, 38] {
            let time = Time::default();
            let model = Model::ready(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert!(matches!(
                hw.configure_phy(None, false),
                Err(Error::Script(_))
            ));
            for nth in [15, 30, 45] {
                let time = Time::default();
                let mut model = Model::ready(&time);
                model.fail_phy_at = nth;
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_ne!(model.state.borrow().phy[&(0, 0)], 0x1200);
            }
            let ports = &[CSI_ADDRESS, EPHY_ACCESS, ERI_ADDRESS];
            for &port in ports {
                let time = Time::default();
                let mut model = Model::ready(&time);
                model.fault = Some(port);
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_mac(None),
                    Err(Error::Device(BlockError::Timeout))
                );
                let s = model.state.borrow();
                assert_eq!(s.bytes[CONFIG_LOCK], 0);
                assert!(
                    !s.writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        TX_HIGH | TX_LOW | RX_HIGH | RX_LOW | COMMAND
                    ))
                );
            }
        }
    }
    #[test]
    fn runtime_link_patch_failure_permanently_blocks_work_after_late_completion() {
        for version in [34, 35, 36, 38] {
            let time = Time::default();
            let mut model = Model::ready(&time);
            model.state.borrow_mut().bytes[PHY_STATUS] = 0x12;
            model.fail_eri_at = 2;
            let mut link = RuntimeLink::default();
            {
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(link.update(&hw), Err(BlockError::Timeout));
            }
            {
                let s = model.state.borrow();
                assert_eq!(s.eri[&0x1bc], 0x11);
                assert!(!s.eri.contains_key(&0x1dc));
                assert!(s.pending.is_some());
                assert_eq!(s.eri_commands, 2);
            }
            // The timed-out write completes after the caller has lost its
            // completion observation. Completion is not a recovery boundary.
            model.fail_eri_at = usize::MAX;
            time.delay(100);
            model.read32(ERI_ADDRESS);
            let writes = model.state.borrow().writes.len();
            assert_eq!(model.state.borrow().eri[&0x1dc], 5);
            model.state.borrow_mut().bytes[PHY_STATUS] = 0x0a;
            let hw = Hardware::new(&model, &time, revision(version), 0);
            for _ in 0..3 {
                assert!(!link.update(&hw).unwrap_or(false)); // carrier gate
                let transmit = link.update(&hw).map(|_| model.write8(TX_POLL, POLL_NORMAL));
                assert_eq!(transmit, Err(BlockError::Timeout));
                let receive = link
                    .update(&hw)
                    .map(|_| panic!("descriptor access after failure"));
                assert_eq!(receive, Err(BlockError::Timeout));
            }
            assert_eq!(model.state.borrow().writes.len(), writes);
            assert_eq!(model.state.borrow().eri_commands, 2);
        }
    }
    #[test]
    fn e_phy_programs_exact_analogue_state_with_observable_unsupported_optional_cleanup() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [32, 33] {
            let time = Time::default();
            let model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                s.parameters.insert(0x8b85, 0xffff);
                s.extended.insert((0x20, 0x15), 0xffff);
                s.extended.insert((0x2d, 0x18), 0x8000);
                s.phy.insert((2, 8), 0xffff);
                // Sentinel register values: no C22 MMD substitute may touch them.
                s.phy.insert((0, 13), 0x7711);
                s.phy.insert((0, 14), 0x8822);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Ok(Some(Warning::EeeAdvertisementDisableUnavailable))
            );
            let s = model.state.borrow();
            assert_eq!(s.parameters[&0x8b80], 0xc896);
            assert_eq!(s.parameters[&0x8b85], 0xdfff);
            assert_eq!(s.phy[&(1, 0xb)], 0x6c20);
            assert_eq!(s.phy[&(3, 0x14)], 0x6420);
            assert_eq!(s.phy[&(2, 8)], 0x80ff);
            assert_eq!(s.extended[&(0x2f, 0x15)], 0x1919);
            assert_eq!(s.extended[&(0xac, 0x18)], 6);
            assert_eq!(s.extended[&(0x23, 0x17)], 6);
            assert_eq!(s.extended[&(0x20, 0x15)], 0xeeff);
            assert_eq!(s.extended[&(0x2d, 0x18)], 0x8050);
            assert_eq!(s.phy[&(6, 0)], 0x5a00);
            assert_eq!(s.phy[&(0, 13)], 0x7711);
            assert_eq!(s.phy[&(0, 14)], 0x8822);
            assert_eq!(s.phy[&(0, 0)], 0x1200);
            assert_eq!(s.page, 0);
            assert!(!s.writes.iter().any(|(r, _, _)| *r == PHY_OCP));
            let message = format!("{}", Warning::EeeAdvertisementDisableUnavailable);
            assert!(message.contains("unsupported"));
            assert!(message.contains("unverified"));
        }
    }

    #[test]
    fn e_mac_start_and_receive_modes_clear_inherited_jumbo_and_pulse_fifo_reset() {
        use crate::bus::dma::RegionAllocator;
        for version in [32, 33] {
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all descriptor use and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            let time = Time::default();
            let model = Model::ready(&time);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xffff);
                s.bytes[CONFIG3] = 0xff;
                s.bytes[CONFIG4] = 0xff;
                s.bytes[CONFIG5] = 0xff;
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.ephy[0], 0xfdff);
                assert_eq!(s.ephy[3], 0xa7ff);
                assert_eq!(s.ephy[0x19], 0xfe6c);
                assert_eq!(s.bytes[CONFIG3] & 4, 0);
                assert_eq!(s.bytes[CONFIG4] & 1, 0);
                assert_eq!(s.bytes[CONFIG5] & 9, 0);
                assert_eq!(s.bytes[EARLY_TX], 0x3f);
                let misc: Vec<_> = s
                    .writes
                    .iter()
                    .filter(|(r, _, _)| *r == MISC)
                    .map(|(_, v, _)| *v)
                    .collect();
                assert_eq!(misc, [1 << 29, 0]);
            }
            publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
            assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
        }
    }

    #[test]
    fn e_warning_does_not_tolerate_required_firmware_phy_or_mac_failures() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [32, 33] {
            let time = Time::default();
            let model = Model::ready(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::Script("RTL8168E requires firmware"))
            );
            for nth in [15, 35, 55] {
                let time = Time::default();
                let mut model = Model::ready(&time);
                model.fail_phy_at = nth;
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_ne!(model.state.borrow().phy[&(0, 0)], 0x1200);
            }
            let time = Time::default();
            let model = Model::ready(&time);
            model.state.borrow_mut().phy.insert((0, 3), 0xc912);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Err(Error::UnsupportedPhy(0x001c_c912))
            );
            for port in [CSI_ADDRESS, EPHY_ACCESS] {
                let time = Time::default();
                let mut model = Model::ready(&time);
                model.fault = Some(port);
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(
                    hw.configure_mac(None),
                    Err(Error::Device(BlockError::Timeout))
                );
                assert_eq!(model.read8(CONFIG_LOCK), 0);
            }
        }
    }
    #[test]
    fn modern_ocp_protocol_preserves_data_bit15_and_uses_independent_physical_addresses() {
        use firmware::ScriptIo;
        for version in [40, 42, 44] {
            let time = Time::default();
            let model = Model::modern(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.phy_write(PHY_PAGE, 0x0a43).unwrap();
            hw.phy_write(0x10, 0x8001).unwrap();
            hw.phy_write(0x0f, 0xffff).unwrap();
            hw.phy_write(0x1e, 0x9876).unwrap();
            assert_eq!(hw.phy_read(0x10).unwrap(), 0x8001);
            assert_eq!(hw.phy_read(0x0f).unwrap(), 0xffff);
            let s = model.state.borrow();
            assert_eq!(s.phy_ocp[&0xa430], 0x8001);
            assert_eq!(s.phy_ocp[&0xa42e], 0xffff);
            assert_eq!(s.phy_ocp[&0xa44c], 0x9876);
            drop(s);
            hw.mac_ocp_write(0xe8de, 0xffff).unwrap();
            assert_eq!(hw.mac_ocp_read(0xe8de).unwrap(), 0xffff);
            assert_eq!(model.state.borrow().mac[&0xe8de], 0xffff);
            assert!(!model.state.borrow().mac.contains_key(&0xe8df));
            hw.write(true, PHY_PAGE, 0x0f80).unwrap();
            hw.write(true, 0, 0x8123).unwrap();
            assert_eq!(hw.read(true, 0).unwrap(), 0x8123);
            assert_eq!(model.state.borrow().mac[&0xf800], 0x8123);
            hw.restore();
            hw.phy_write(PHY_PAGE, 0).unwrap();
            assert_eq!(hw.phy_read(2).unwrap(), 0x001c);
        }
    }

    #[test]
    fn mac40_bmcr_quirk_precedes_each_phy_ocp_write_and_fails_before_power_transition() {
        for (control, expected) in [
            (0x0800, 0x03ff_ffff),
            (0x1000, u32::MAX),
            (0x8800, u32::MAX),
        ] {
            let time = Time::default();
            let model = Model::modern(&time);
            model.state.borrow_mut().eri.insert(0x1a8, u32::MAX);
            let hw = Hardware::new(&model, &time, revision(40), 0);
            hw.phy_write(PHY_CONTROL, control).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.eri[&0x1a8], expected);
            let last_eri = s
                .writes
                .iter()
                .rposition(|(r, _, _)| *r == ERI_ADDRESS)
                .unwrap();
            let phy = s.writes.iter().position(|(r, _, _)| *r == PHY_OCP).unwrap();
            assert!(last_eri < phy);
        }
        let time = Time::default();
        let mut model = Model::modern(&time);
        model.fault = Some(ERI_ADDRESS);
        let hw = Hardware::new(&model, &time, revision(40), 0);
        assert_eq!(hw.phy_write(PHY_CONTROL, 0x1000), Err(BlockError::Timeout));
        assert!(
            !model
                .state
                .borrow()
                .writes
                .iter()
                .any(|(r, _, _)| *r == PHY_OCP)
        );
        let model = Model::modern(&time);
        let hw = Hardware::new(&model, &time, revision(42), 0);
        hw.phy_write(PHY_CONTROL, 0x1000).unwrap();
        assert!(
            !model
                .state
                .borrow()
                .writes
                .iter()
                .any(|(r, _, _)| *r == ERI_ADDRESS)
        );
    }

    #[test]
    fn modern_initial_ownership_requires_both_empty_fifos_and_two_fresh_shared_ready_events() {
        for version in [40, 42, 44, 46] {
            let time = Time::default();
            let model = Model::modern(&time);
            model.state.borrow_mut().mac.insert(0xe8de, 0xffff);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.initialize_modern().unwrap();
            let s = model.state.borrow();
            assert_eq!(s.mac[&0xe8de], 0xbfff);
            assert_eq!(s.bytes[MCU] & 0x82, 2);
            assert_eq!(s.bytes[COMMAND] & ENABLE, 0);
            assert!(time.now() >= 3_800);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
            drop(s);
            for broken in [TX_CONFIG, MCU, MAC_OCP] {
                let time = Time::default();
                let mut model = Model::modern(&time);
                if broken == TX_CONFIG {
                    Model::store32(&mut model.state.borrow_mut(), TX_CONFIG, 0);
                }
                if broken == MCU {
                    model.state.borrow_mut().bytes[MCU] = 0x20;
                }
                if broken == MAC_OCP {
                    model.shared_ready_delay = None;
                }
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.initialize_modern(), Err(BlockError::Timeout));
                assert!(time.now() < 15_000);
                assert!(
                    !model.state.borrow().writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                    ))
                );
            }
        }
    }

    #[test]
    fn g_phy_mask_branches_and_post_reset_eee_cleanup_use_real_ocp_state() {
        let script_bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&script_bytes).unwrap();
        for version in [40, 42, 44] {
            for capability in [0, 0x100] {
                let time = Time::default();
                let model = Model::modern(&time);
                {
                    let mut s = model.state.borrow_mut();
                    s.phy_ocp.extend([
                        (0xa460, capability),
                        (0xa466, capability),
                        (0xbcc4, 0xffff),
                        (0xc41a, 0xffff),
                        (0xbcc8, 0xffff),
                        (0xc422, 0xffff),
                        (0xa5d0, 0xffff),
                    ]);
                    s.g_parameters.insert(0x8084, 0xffff);
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
                let s = model.state.borrow();
                assert_eq!(s.phy_ocp[&0xa42c], 0xa55a); // standard PHY reg22.
                assert_eq!(s.phy_ocp[&0xa400], 0x1200);
                assert_eq!(s.phy_ocp[&0xa5d0], 0);
                assert_eq!(s.phy_ocp[&0xa432] & 0x10, 0x10);
                if version == 40 {
                    assert_eq!(
                        s.phy_ocp[&0xbcc4] & 0x8000,
                        if capability == 0 { 0x8000 } else { 0 }
                    );
                    assert_eq!(s.phy_ocp[&0xc41a] & 2, if capability == 0 { 0 } else { 2 });
                    assert_eq!(s.phy_ocp[&0xbcc8], 0xfeff);
                    assert_eq!(s.g_parameters[&0x8084], 0x9fff);
                    assert_eq!(s.g_parameters[&0x8012] & 0x8000, 0x8000);
                    assert_eq!(s.phy_ocp[&0xc422], 0xdfff);
                    assert_eq!(s.phy_ocp[&0xbcd8], 0x1065);
                } else {
                    assert_eq!(s.phy_ocp[&0xbcc4], 0xffff);
                    assert!(!s.g_parameters.contains_key(&0x8012));
                }
                let reset = s
                    .writes
                    .iter()
                    .rposition(|(r, v, _)| {
                        *r == PHY_OCP && (*v >> 15) as u16 & !1 == 0xa400 && *v & (1 << 15) != 0
                    })
                    .unwrap();
                let eee = s
                    .writes
                    .iter()
                    .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd2e8_0000)
                    .unwrap();
                assert!(reset < eee);
            }
        }
    }
    #[test]
    fn g_mac_sequences_include_exact_8411b_rx_fix_before_any_descriptor_publication() {
        use crate::bus::dma::RegionAllocator;
        for version in [40, 42, 44] {
            let time = Time::default();
            let model = Model::modern(&time);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xffff);
                s.bytes[CONFIG3] = 0x7f;
                s.eri
                    .extend([(0xcc, 0xaabb_ccdd), (0xd0, 0x1122_3344), (0x1b0, 0xffff)]);
                s.mac.insert(0xc0ac, 0x8000);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.initialize_modern().unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.bytes[CONFIG_LOCK], 0);
                assert_eq!(s.bytes[CONFIG3] & 2, 0);
                assert_eq!(s.eri[&0xc8], 0x0008_0002);
                assert_eq!(s.eri[&0xe8], 0x0010_0006);
                assert_eq!(s.eri[&0xcc], 0xaabb_cc38);
                assert_eq!(s.eri[&0xd0], 0x1122_3348);
                assert_eq!(s.eri[&0x2f8], 0x1d8f);
                assert_eq!(s.eri[&0x1b0] & 0x1003, 0);
                assert_eq!(s.mac[&0xc0ac], 0x9f80);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
                if version == 44 {
                    assert_eq!(s.ephy[0xc], 0xc82f);
                    assert_eq!(s.mac[&0xf800], 0xe008);
                    assert_eq!(s.mac[&0xf8dc], 0x0132);
                    assert_eq!(s.mac.range(0xf800..=0xf8dc).count(), 111);
                    assert_eq!(s.mac[&0xfc26], 0x8000);
                    assert_eq!(s.mac[&0xfc36], 0x012d);
                    let at = |value| {
                        s.writes
                            .iter()
                            .position(|(r, v, _)| *r == MAC_OCP && *v == value)
                            .unwrap()
                    };
                    assert!(at(0xfe13_0000) < at(0xfc00_e008)); // FC26 off before first patch word.
                    assert!(at(0xfc6e_0132) < at(0xfe13_8000)); // Last word before enabling fix.
                } else if version == 42 {
                    assert_eq!(s.ephy[0], 0x10a3);
                    assert_eq!(s.ephy[0x1e], 0x20eb);
                    assert!(!s.mac.contains_key(&0xfc26));
                } else {
                    assert_eq!(s.ephy[0xc], 0xc82f);
                    assert_eq!(s.ephy[0x19], 0x7fff);
                }
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives descriptor use and has no competing access.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            let mac = read_station(&hw).unwrap();
            publish(&hw, &rx, &tx, mac).unwrap();
            assert_eq!(
                model.read32(RX_CONFIG),
                (1 << 15) | (1 << 14) | (1 << 11) | (7 << 8) | 0x0e
            );
            assert_eq!(
                model.read32(RX_HIGH),
                (rx.descriptors.physical() >> 32) as u32
            );
        }
    }

    #[test]
    fn modern_required_protocol_failures_never_become_warnings_or_publish_dma() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [40, 42, 44, 46] {
            for port in [PHY_OCP, ERI_ADDRESS, EPHY_ACCESS, CSI_ADDRESS] {
                let time = Time::default();
                let mut model = Model::modern(&time);
                model.fault = Some(port);
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                if port == PHY_OCP {
                    assert_eq!(
                        hw.configure_phy(Some(&script), false),
                        Err(Error::Device(BlockError::Timeout))
                    );
                } else {
                    assert_eq!(
                        hw.configure_mac(None),
                        Err(Error::Device(BlockError::Timeout))
                    );
                    assert_eq!(model.read8(CONFIG_LOCK), 0);
                }
                assert!(
                    !model
                        .state
                        .borrow()
                        .writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
            let time = Time::default();
            let mut model = Model::modern(&time);
            model.failed_read = Some(MAC_OCP);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.initialize_modern(),
                Err(BlockError::Device { status: u32::MAX })
            );
            let model = Model::modern(&time);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::Script(if version == 46 {
                    "RTL8168H/M requires firmware"
                } else {
                    "RTL8168G/8411B requires firmware"
                }))
            );
            model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc912);
            assert_eq!(
                hw.configure_phy(Some(&script), false),
                Err(Error::UnsupportedPhy(0x001c_c912))
            );
        }
        let time = Time::default();
        let mut model = Model::modern(&time);
        model.failed_read = Some(PHY_OCP);
        let hw = Hardware::new(&model, &time, revision(40), 0);
        assert_eq!(hw.phy_read(2), Err(BlockError::Device { status: u32::MAX }));
        assert!(hw.phy_ocp_read(1).is_err());
        assert!(hw.mac_ocp_write(1, 0).is_err());
    }
    #[test]
    fn dp_mdio_guard_preserves_actual_identity_and_relocks_on_timeout() {
        for version in [28, 31] {
            let time = Time::default();
            let mut model = Model::dp(&time, version, false);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.phy_read(3).unwrap(), 0xc800);
            assert_eq!(
                hw.configure_phy(None, false).unwrap(),
                Some(Warning::DpPhyIdentityCorrected {
                    reported: 0x001c_c800,
                    selected: 0x001c_c912
                })
            );
            assert_eq!(hw.phy_read(3).unwrap(), 0xc800);
            {
                let s = model.state.borrow();
                assert_eq!(s.phy[&(0, 3)], 0xc800);
                assert_eq!(s.phy[&(0, 14)], 0); // actual RTL8211B resume quirk.
                assert_eq!(s.phy[&(0, 0)], 0x1200);
                assert_eq!(
                    Model::raw32(&s, DP_MDIO_GATE) & DP_MDIO_GATED,
                    DP_MDIO_GATED
                );
                if version == 28 {
                    assert_eq!(s.phy[&(1, 0x17)], 0x0cc0);
                    assert_eq!(s.extended[&(0x2d, 0x18)], 0x40);
                    assert_eq!(s.phy[&(0, 0x0d)] & 0x20, 0x20);
                } else {
                    assert!(!s.phy.contains_key(&(1, 0x17)));
                }
            }
            model.fault = Some(PHY_ACCESS);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.phy_read(3), Err(BlockError::Timeout));
            assert_eq!(model.read32(DP_MDIO_GATE) & DP_MDIO_GATED, DP_MDIO_GATED);
            let model = Model::dp(&time, version, false);
            model.state.borrow_mut().phy.insert((0, 3), 0xc913);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::UnsupportedPhy(0x001c_c913))
            );
            let model = Model::dp(&time, version, false);
            model.state.borrow_mut().phy.insert((0, 3), 0xc912);
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.configure_phy(None, false).unwrap(), None);
        }
    }

    #[test]
    fn dp_dash_start_notifies_both_modes_and_requires_enabled_management_acknowledgement() {
        for version in [28, 31] {
            for dash in [false, true] {
                let time = Time::default();
                let model = Model::dp(&time, version, dash);
                let hw = Hardware::new(&model, &time, revision(version), 0);
                hw.dp_start().unwrap();
                let s = model.state.borrow();
                assert_eq!(s.eri[&0xe8] & 0xff, 5);
                assert_eq!(s.dp_ocp[&0x30], 1);
                let reg = if version == 31 { 0xb8 } else { 0x10 };
                assert_eq!(s.dp_ocp[&reg] & (1 << 11) != 0, dash);
                if dash {
                    assert!(time.now() >= 20_000);
                } else {
                    assert!(time.now() < 1_000);
                }
                assert!(!s.writes.iter().any(|(r, _, _)| matches!(
                    *r,
                    PHY_ACCESS | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                )));
            }
            let time = Time::default();
            let mut model = Model::dp(&time, version, true);
            model.dp_ready_delay = None;
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.dp_start(), Err(BlockError::Timeout));
            assert!(time.now() < 110_000);
            assert_eq!(model.state.borrow().eri[&0xe8] & 0xff, 5); // No blind stop/retry.
        }
    }

    #[test]
    fn dp_incomplete_notification_is_not_retried_even_if_it_later_completes() {
        for version in [28, 31] {
            let time = Time::default();
            let mut model = Model::dp(&time, version, true);
            model.fail_dp_at = 2;
            {
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.dp_start(), Err(BlockError::Timeout));
            }
            assert_eq!(model.state.borrow().dp_commands, 2);
            let count = model.state.borrow().writes.len();
            model.fail_dp_at = usize::MAX;
            time.delay(50_000);
            model.read32(DP_OCP_ACCESS);
            assert_eq!(model.state.borrow().dp_ocp[&0x30], 1);
            assert_eq!(model.state.borrow().writes.len(), count);
            assert_eq!(model.state.borrow().eri[&0xe8] & 0xff, 5);
        }
    }

    #[test]
    fn dp_exact_mac_settings_preserve_ephy_bits_and_publish_only_after_management_ready() {
        use crate::bus::dma::RegionAllocator;
        for version in [28, 31] {
            assert!(revision(version).implemented());
            assert!(revision(version).firmware.is_none());
            let time = Time::default();
            let model = Model::dp(&time, version, true);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xabcd);
                s.bytes[CONFIG3] = 0xff;
                s.bytes[CONFIG4] = 0xff;
                s.eri.insert(0xe8, 0xdead_be00);
                s.dp_ocp.insert(0x30, 0xdead_be00);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.reset().unwrap();
            hw.dp_start().unwrap();
            hw.configure_phy(None, false).unwrap();
            hw.reset().unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.eri[&0xe8], 0xdead_be05);
                assert_eq!(s.dp_ocp[&0x30], 0xdead_be01);
                assert_eq!(s.bytes[CONFIG3] & 4, 0);
                assert_eq!(s.bytes[CONFIG4], if version == 31 { 0xfe } else { 0xff });
                assert_eq!(s.bytes[EARLY_TX], 0x3f);
                assert_eq!(s.bytes[CONFIG_LOCK], 0);
                if version == 28 {
                    for (reg, clear, set) in [
                        (0xb, 0, 0x48),
                        (0x19, 0x20, 0x50),
                        (0xc, 0x100, 0x20),
                        (0x10, 4, 0),
                    ] {
                        assert_eq!(s.ephy[reg], (0xabcd & !clear) | set);
                    }
                } else {
                    assert_eq!(s.ephy, [0xabcd; 32]);
                    assert!(!s.writes.iter().any(|(r, _, _)| *r == EPHY_ACCESS));
                }
                let notified = s
                    .writes
                    .iter()
                    .position(|(r, v, _)| *r == DP_OCP_ACCESS && *v == 0x8000_1030)
                    .unwrap();
                let phy = s
                    .writes
                    .iter()
                    .position(|(r, _, _)| *r == PHY_ACCESS)
                    .unwrap();
                assert!(notified < phy);
                assert!(!s.writes.iter().any(|(r, v, _)| matches!(
                    *r,
                    TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                ) || (*r == COMMAND
                    && *v == u32::from(ENABLE))));
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives descriptors and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
            assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
            let s = model.state.borrow();
            let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
            assert!(at(TX_HIGH) < at(TX_LOW));
            assert!(at(RX_HIGH) < at(RX_LOW));
            assert!(
                s.writes
                    .iter()
                    .rposition(|(r, v, _)| *r == COMMAND && *v == u32::from(ENABLE))
                    .unwrap()
                    > at(RX_LOW)
            );
            assert!(time.now() >= 90_000);
        }
    }

    #[test]
    fn dp_management_gate_and_mac_errors_fail_before_dma_publication() {
        for version in [28, 31] {
            for port in [DP_OCP_ACCESS, DP_OCP_DATA, ERI_ADDRESS] {
                let time = Time::default();
                let mut model = Model::dp(&time, version, true);
                model.failed_read = Some(port);
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.dp_start(), Err(BlockError::Device { status: u32::MAX }));
                assert!(
                    !model.state.borrow().writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        PHY_ACCESS | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                    ))
                );
            }
            let time = Time::default();
            let mut model = Model::dp(&time, version, false);
            model.failed_read = Some(DP_MDIO_GATE);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.phy_read(2), Err(BlockError::Device { status: u32::MAX }));
            assert!(model.state.borrow().writes.is_empty());
            let time = Time::default();
            let mut model = Model::dp(&time, version, false);
            model.fault = Some(if version == 28 {
                EPHY_ACCESS
            } else {
                CSI_ADDRESS
            });
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_mac(None),
                Err(Error::Device(BlockError::Timeout))
            );
            assert_eq!(model.read8(CONFIG_LOCK), 0);
            assert!(
                !model
                    .state
                    .borrow()
                    .writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
    }

    #[test]
    fn clock_request_uses_narrow_link_control_and_rejects_failed_config_reads() {
        struct Config {
            value: u16,
            writes: Vec<(u16, u16)>,
        }
        impl ConfigSpace for Config {
            fn read32(&self, _: u16) -> u32 {
                panic!("must use narrow access")
            }
            fn write32(&mut self, _: u16, _: u32) {
                panic!("must use narrow access")
            }
            fn read16(&self, offset: u16) -> u16 {
                assert_eq!(offset, 0x82);
                self.value
            }
            fn write16(&mut self, offset: u16, value: u16) {
                self.writes.push((offset, value));
                self.value = value;
            }
        }
        let mut config = Config {
            value: 0xa5fc,
            writes: Vec::new(),
        };
        clock_request(&mut config, 0x82, false).unwrap();
        assert_eq!(config.value, 0xa4fc);
        clock_request(&mut config, 0x82, true).unwrap();
        assert_eq!(config.value, 0xa5fc);
        assert_eq!(config.writes, [(0x82, 0xa4fc), (0x82, 0xa5fc)]);
        config.value = u16::MAX;
        assert_eq!(
            clock_request(&mut config, 0x82, true),
            Err(BlockError::Device { status: 65535 })
        );
        assert_eq!(config.writes.len(), 2);
    }

    #[test]
    fn dp_phy_failure_blocks_page_cleanup_and_further_transactions_after_late_state_change() {
        for version in [28, 31] {
            let time = Time::default();
            let mut model = Model::dp(&time, version, false);
            model.fail_phy_at = 15;
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.configure_phy(None, false),
                Err(Error::Device(BlockError::Timeout))
            );
            assert_eq!(model.state.borrow().mdio_commands, 15);
            let writes = model.state.borrow().writes.len();
            // Model a late command result, including a changed current page.
            time.delay(50_000);
            {
                let mut s = model.state.borrow_mut();
                s.pending = None;
                s.page = 7;
                Model::store32(&mut s, PHY_ACCESS, ACCESS | 0xc800);
            }
            assert!(hw.phy_read(3).is_err());
            assert!(hw.phy_write(PHY_PAGE, 0).is_err());
            assert_eq!(model.state.borrow().writes.len(), writes);
            assert_eq!(model.state.borrow().page, 7);
            assert_eq!(model.read32(DP_MDIO_GATE) & DP_MDIO_GATED, DP_MDIO_GATED);
        }
    }

    #[test]
    fn h_phy_adc_bias_sentinel_rlen_and_masks_use_actual_calibration_values() {
        for xid in [0x541, 0x6c0] {
            let detected = revision::detect(xid << 20).unwrap();
            assert_eq!(detected.version, 46);
            assert!(detected.implemented());
            assert_eq!(detected.firmware, Some("rtl_nic/rtl8168h-2.fw"));
            assert_eq!(u32::from(detected.xid), xid);
        }
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for (adc1, adc2, bias) in [
            (0x80, 0x1234, Some(0x891c)),
            (0, 0, Some(0)),
            (0x80, 0xffff, None),
        ] {
            for (rlen, expected) in [(0, 0), (3, 0), (4, 0x1111), (15, 0xcccc)] {
                let time = Time::default();
                let mut model = Model::modern(&time);
                model.h_adc = Some((adc1, adc2));
                {
                    let mut s = model.state.borrow_mut();
                    s.g_parameters.extend([(0x808a, 0xffff), (0x0811, 1)]);
                    s.phy_ocp.extend([
                        (0xbcdc, 0xfff0 | rlen),
                        (0xbcfc, 0x7654),
                        (0xa442, 0xffff),
                        (0xa430, 0xffff),
                        (0xa5d0, 0xffff),
                    ]);
                }
                let mut hw = Hardware::new(&model, &time, revision(46), 0);
                assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
                let s = model.state.borrow();
                assert_eq!(s.g_parameters[&0x808a], 0xffca);
                assert_eq!(s.g_parameters[&0x0811], 0x0801);
                assert_eq!(s.phy_ocp[&0xbcfc], bias.unwrap_or(0x7654));
                assert_eq!(s.phy_ocp[&0xbcde], expected);
                assert_eq!(s.phy_ocp[&0xa442], 0xff7f);
                assert_eq!(s.phy_ocp[&0xa430], 0xfffa);
                assert_eq!(s.phy_ocp[&0xa5d0], 0);
                assert_eq!(s.phy_ocp[&0xa400], 0x1200);
                assert_eq!(s.mac[&0xdd02], 0x807d);
                if bias.is_none() {
                    assert!(!s.writes.iter().any(|(r, v, _)| *r == PHY_OCP
                        && *v & ACCESS != 0
                        && (*v >> 15) as u16 & !1 == 0xbcfc));
                }
            }
        }
    }

    #[test]
    fn h_mac_saw_count_timer_masks_and_ephy_complete_before_dma() {
        use crate::bus::dma::RegionAllocator;
        for saw in [0, 1, 1000, 0x3fff] {
            let time = Time::default();
            let model = Model::modern(&time);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xffff);
                s.bytes[DLL_POWER] = 0xfe;
                s.bytes[MISC_1] = 0xfe;
                s.bytes[CONFIG3] = 0x7f;
                s.phy_ocp.insert(0xc426, saw | 0xc000);
                s.mac.extend([
                    (0xd412, 0xf812),
                    (0xe092, 0xabc4),
                    (0xe052, 0x7fff),
                    (0xe056, 0xffff),
                    (0xe0d6, 0xffff),
                    (0xd420, 0xffff),
                ]);
                s.eri.extend([(0x5f0, 0xabcd_0000), (0x1b0, 0x1003)]);
            }
            let mut hw = Hardware::new(&model, &time, revision(46), 0);
            hw.initialize_modern().unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.ephy[0x1e], 0xf7ff);
                assert_eq!(s.ephy[0x1d], 0xffff);
                for (reg, value) in [(5, 0x2089), (6, 0x5881), (4, 0x854a), (1, 0x068b)] {
                    assert_eq!(s.ephy[reg], value);
                }
                assert_eq!(s.eri[&0x5f0], 0xabcd_4f87);
                assert_eq!(s.eri[&0x1b0], 0);
                assert_eq!(s.bytes[DLL_POWER], 0x3e);
                assert_eq!(s.bytes[MISC_1], 0xb6); // MISC DWORD's RXDV gate shares byte f2 bit3.
                assert_eq!(s.mac[&0xe092], 0xab00);
                assert_eq!(s.mac[&0xe048], 1546);
                assert_eq!(
                    s.mac[&0xd412],
                    if saw == 0 {
                        0xf812
                    } else {
                        0xf000 | ((16_000_000 / u32::from(saw)) & 0xfff) as u16
                    }
                );
                assert_eq!(s.mac[&0xe052], 0x9fff);
                assert_eq!(s.mac[&0xe056], 0xff0f);
                assert_eq!(s.mac[&0xe0d6], 0xff7f);
                assert_eq!(s.mac[&0xd420], 0xf47f);
                let pulse: Vec<_> = s
                    .writes
                    .iter()
                    .filter(|(r, v, _)| {
                        *r == MAC_OCP && (*v >> 15) as u16 & !1 == 0xe63e && *v & ACCESS != 0
                    })
                    .map(|(_, v, _)| *v as u16)
                    .collect();
                assert_eq!(pulse, [1, 0]);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives descriptor access and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
            assert_eq!(
                model.read32(RX_CONFIG),
                (1 << 15) | (1 << 14) | (1 << 11) | (7 << 8) | 0x0e
            );
        }
    }

    #[test]
    fn h_calibration_failed_bus_read_and_runtime_tx_lpi_failure_remain_errors() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        let time = Time::default();
        let mut model = Model::modern(&time);
        model.failed_read = Some(MAC_OCP);
        let mut hw = Hardware::new(&model, &time, revision(46), 0);
        assert_eq!(
            hw.configure_phy(Some(&script), false),
            Err(Error::Device(BlockError::Device { status: u32::MAX }))
        );
        assert_ne!(model.state.borrow().phy_ocp[&0xa400], 0x1200);
        for version in [46, 51, 52] {
            let time = Time::default();
            let mut model = Model::modern(&time);
            model.fail_eri_at = 2;
            model.state.borrow_mut().bytes[PHY_STATUS] = 0x12;
            let mut link = RuntimeLink::default();
            {
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(link.update(&hw), Err(BlockError::Timeout));
            }
            let writes = model.state.borrow().writes.len();
            model.fail_eri_at = usize::MAX;
            time.delay(50_000);
            model.read32(ERI_ADDRESS);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(link.update(&hw), Err(BlockError::Timeout));
            assert_eq!(model.state.borrow().writes.len(), writes);
        }
    }

    #[test]
    fn ep_cmac_stop_acknowledges_w1c_before_shared_fifo_and_is_bounded_on_failure() {
        for version in [51, 52] {
            let time = Time::default();
            let model = Model::ep(&time, version, false);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.initialize_modern().unwrap();
            let s = model.state.borrow();
            assert_eq!(s.bytes[IBCR0], 0x84);
            assert_eq!(s.bytes[IBCR2], 0x84);
            assert_eq!(s.bytes[IBISR0] & 0x20, 0);
            let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
            assert!(at(IBCR2) < at(IBISR0));
            assert!(at(IBISR0) < at(IBCR0));
            assert!(at(IBCR0) < at(MISC));
            assert!(time.now() >= 100_000);
            drop(s);
            let time = Time::default();
            let mut model = Model::ep(&time, version, false);
            model.cmac_ready_delay = None;
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.initialize_modern(), Err(BlockError::Timeout));
            assert_eq!(time.now(), 100_000_000);
            assert_eq!(model.state.borrow().writes, [(IBCR2, 0x84, 1)]);
            let time = Time::default();
            let mut model = Model::ep(&time, version, false);
            model.failed_read = Some(IBISR0);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                hw.initialize_modern(),
                Err(BlockError::Device { status: 255 })
            );
            assert_eq!(model.state.borrow().writes, [(IBCR2, 0x84, 1)]);
        }
    }

    #[test]
    fn ep_oob_namespace_fp_base_masks_and_conditional_ack_are_real_and_fallible() {
        for version in [51, 52] {
            for enabled in [false, true] {
                let time = Time::default();
                let model = Model::ep(&time, version, enabled);
                {
                    let mut s = model.state.borrow_mut();
                    s.oob.extend([(0x180, 0xaabb_cc00), (0x30, 0x7654_3202)]);
                    s.eri.extend([(0x180, 0x1122_3344), (0x30, 0x5566_7788)]);
                }
                let hw = Hardware::new(&model, &time, revision(version), 0);
                hw.ep_start().unwrap();
                let s = model.state.borrow();
                assert_eq!(s.oob[&0x180], 0xaabb_cc05);
                assert_eq!(s.oob[&0x30], 0x7654_3203);
                assert_eq!(s.eri[&0x180], 0x1122_3344);
                assert_eq!(s.eri[&0x30], 0x5566_7788);
                assert_eq!(s.oob.get(&0x124).copied().unwrap_or(0) & 1 != 0, enabled);
                assert!(
                    !s.writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                    ))
                );
            }
            let time = Time::default();
            let mut model = Model::ep(&time, version, true);
            model.ep_ready_delay = None;
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.ep_start(), Err(BlockError::Timeout));
            assert!(time.now() < 310_000);
            assert_eq!(model.state.borrow().oob[&0x180] & 0xff, 5);
            for port in [ERI_ADDRESS, ERI_DATA] {
                let time = Time::default();
                let mut model = Model::ep(&time, version, true);
                model.failed_read = Some(port);
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.ep_start(), Err(BlockError::Device { status: u32::MAX }));
            }
        }
    }

    #[test]
    fn ep_and_fp_phy_masks_and_pwm_paths_are_distinct_without_early_mac_firmware() {
        for version in [51, 52] {
            let time = Time::default();
            let model = Model::ep(&time, version, false);
            {
                let mut s = model.state.borrow_mut();
                for address in [0x8084, 0x80f3, 0x80d7, 0x808b, 0x809b, 0x80ad, 0x80b0] {
                    s.g_parameters.insert(address, 0xffff);
                }
                s.phy_ocp
                    .extend([(0xbcc8, 0xffff), (0xc422, 0xffff), (0xa430, 0xffff)]);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(hw.configure_phy(None, false).unwrap(), None);
            let s = model.state.borrow();
            assert_eq!(s.phy_ocp[&0xa400], 0x1200);
            assert_eq!(s.phy_ocp[&0xa5d0], 0);
            assert!(!s.writes.iter().any(|(r, _, _)| *r == MAC_OCP));
            if version == 51 {
                assert_eq!(s.g_parameters[&0x80f3], 0x8bff);
                assert_eq!(s.g_parameters[&0x80d7], 0x84ff);
                assert_eq!(s.g_parameters[&0x8084], 0x9fff);
                assert_eq!(s.phy_ocp[&0xc422], 0xdfff);
                assert_eq!(s.phy_ocp[&0xbcc8], 0xfeff);
                assert_eq!(s.phy_ocp[&0xbc84], 0xed);
                assert_eq!(s.phy_ocp[&0xbcd8], 0x1065);
            } else {
                assert_eq!(s.g_parameters[&0x808b], 0xcbff);
                assert_eq!(s.g_parameters[&0x809b], 0xb7ff);
                assert_eq!(s.g_parameters[&0x80ad], 0x9fff);
                assert_eq!(s.g_parameters[&0x80b0], 0x93ff);
                assert_eq!(s.g_parameters[&0x8011] & 0x800, 0x800);
                assert_eq!(s.g_parameters[&0x8016] & 0x400, 0x400);
                assert_eq!(s.phy_ocp[&0xa4a2] & 0x200, 0x200);
                assert_eq!(s.phy_ocp[&0xa428] & 0x80, 0x80);
                assert!(!s.phy_ocp.contains_key(&0xbcd8));
            }
        }
    }

    #[test]
    fn fp_mac_only_firmware_executes_after_mac_pulse_before_exit_l1_and_dma() {
        let bytes: Vec<_> = [0x4000_0001u32, 0x801f_0e00, 0x80d6_a55a]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let script = Script::parse(&bytes).unwrap();
        for xid in [0x54a, 0x54b] {
            let time = Time::default();
            let model = Model::ep(&time, 52, false);
            model.state.borrow_mut().ephy.fill(0xabcd);
            let rev = revision::detect(xid << 20).unwrap();
            let mut hw = Hardware::new(&model, &time, rev, 0);
            hw.initialize_modern().unwrap();
            hw.ep_start().unwrap();
            hw.configure_phy(Some(&script), false).unwrap();
            assert!(!model.state.borrow().mac.contains_key(&0xe0d6));
            hw.configure_mac(Some(&script)).unwrap();
            let s = model.state.borrow();
            assert_eq!(s.ephy[0x19], 0xbb8d);
            let ephy: Vec<_> = s
                .writes
                .iter()
                .filter(|(r, v, _)| *r == EPHY_ACCESS && *v & ACCESS != 0)
                .collect();
            assert_eq!(ephy.len(), 2); // Donor19/59 both encode wire register19.
            assert_eq!(s.mac[&0xea80], 3);
            if xid == 0x54a {
                assert_eq!(s.mac[&0xe0d6], 0xa55a);
                let at = |value| {
                    s.writes
                        .iter()
                        .position(|(r, v, _)| *r == MAC_OCP && *v == value)
                        .unwrap()
                };
                assert!(at(0xf31f_0000) < at(0xf06b_a55a)); // E63E reset pulse before script.
                assert!(at(0xf06b_a55a) < at(0xe056_1f80)); // Script before exit-L1 C0AC.
            } else {
                assert!(!s.mac.contains_key(&0xe0d6));
            }
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
            );
        }
    }

    #[test]
    fn ep_failed_notification_and_fp_missing_or_failed_mac_firmware_never_publish_dma() {
        for version in [51, 52] {
            for nth in 1..=4 {
                let time = Time::default();
                let mut model = Model::ep(&time, version, true);
                model.fail_eri_at = nth;
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.ep_start(), Err(BlockError::Timeout));
                assert!(
                    !model.state.borrow().writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                    ))
                );
                assert!(time.now() < 20_000);
            }
        }
        let bytes: Vec<_> = [0x4000_0001u32, 0x801f_0e00, 0x80d6_a55a]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let script = Script::parse(&bytes).unwrap();
        for fault in 0..3 {
            let time = Time::default();
            let mut model = Model::ep(&time, 52, false);
            if fault == 1 {
                model.fail_mac_address = Some(0xe0d6);
            }
            if fault == 2 {
                model.stuck_phy_reset = true;
                model.state.borrow_mut().phy_ocp.insert(0xa400, PHY_RESET);
            }
            let mut hw = Hardware::new(&model, &time, revision(52), 0);
            let result = hw.configure_mac(if fault == 0 { None } else { Some(&script) });
            assert_eq!(
                result,
                Err(match fault {
                    0 => Error::Script("RTL8117 requires MAC firmware"),
                    1 => Error::Device(BlockError::Device { status: 255 }),
                    _ => Error::Device(BlockError::Timeout),
                })
            );
            let s = model.state.borrow();
            assert_eq!(s.bytes[CONFIG_LOCK], 0);
            assert!(!s.mac.contains_key(&0xc0ac));
            assert!(
                !s.writes.iter().any(|(r, _, _)| matches!(
                    *r,
                    RX_MAXIMUM | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                ))
            );
        }
    }

    #[test]
    fn ep_fp_mac_masks_and_actual_ring_publication_follow_complete_backend_setup() {
        use crate::bus::dma::RegionAllocator;
        for xid in [0x502, 0x54b] {
            let rev = revision::detect(xid << 20).unwrap();
            let time = Time::default();
            let model = Model::ep(&time, rev.version, true);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xffff);
                s.eri
                    .extend([(0xcc, 0xaabb_ccdd), (0xd0, 0x1122_3344), (0x1b0, 0x1003)]);
                s.mac
                    .extend([(0xd3e2, 0xffff), (0xd3e4, 0xffff), (0xe860, 0x1234)]);
            }
            let mut hw = Hardware::new(&model, &time, rev, 0);
            hw.initialize_modern().unwrap();
            hw.ep_start().unwrap();
            hw.configure_phy(None, false).unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.eri[&0xcc], 0xaabb_cc2f);
                assert_eq!(s.eri[&0xd0], 0x1122_335f);
                assert_eq!(s.eri[&0x1b0] & 3, 0);
                if rev.version == 51 {
                    assert_eq!(s.ephy[0], 0xffff);
                    assert_eq!(s.ephy[0xd], 0xfeff);
                    assert_eq!(s.ephy[0x19], 0x7fde);
                    assert_eq!(s.mac[&0xd3e2], 0xf271);
                    assert_eq!(s.mac[&0xd3e4], 0xff00);
                    assert_eq!(s.mac[&0xe860], 0x12b4);
                    assert_eq!(s.eri[&0x2fc], 1);
                } else {
                    assert_eq!(s.eri[&0xd4] & 0x10, 0x10);
                }
                assert_eq!(s.writes.iter().filter(|(r, _, _)| *r == IBISR0).count(), 2);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives descriptor access and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
            assert_eq!(
                model.read32(RX_CONFIG),
                (1 << 15) | (1 << 14) | (1 << 11) | (7 << 8) | 0xe
            );
            for id in [0xc912, 0xc913] {
                let model = Model::ep(&time, rev.version, false);
                model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                let mut hw = Hardware::new(&model, &time, rev, 0);
                assert_eq!(
                    hw.configure_phy(None, false),
                    Err(Error::UnsupportedPhy(0x001c_0000 | u32::from(id)))
                );
            }
        }
    }

    #[test]
    fn nbase_aperture_irq_width_and_doorbell_are_checked_before_extended_io() {
        // The actual shared map_registers boundary checks both BAR size and
        // retained mapping before returning MMIO. The constructor requests the
        // complete range through the 16-bit timer at 6048 before reading it.
        assert_eq!(register_aperture(0x8125), 0x604a);
        assert_eq!(register_aperture(0x8126), 0x604a);
        assert_eq!(register_aperture(0x8168), 256);
        for version in [61, 63, 64, 65] {
            let time = Time::default();
            let model = Model::nbase(&time);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.reset().unwrap();
            kick_transmit(&model, revision(version));
            let s = model.state.borrow();
            assert!(s.writes.contains(&(NBASE_INTERRUPT_MASK, 0, 4)));
            assert!(s.writes.contains(&(NBASE_INTERRUPT_STATUS, u32::MAX, 4)));
            assert!(s.writes.contains(&(NBASE_TX_POLL, 1, 2)));
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, w)| (*r == TX_POLL && *w == 1)
                        || (*r == INTERRUPT_STATUS && *w == 2))
            );
        }
    }

    #[test]
    fn nbase_initial_fifo_and_new_b_shared_status_require_real_completion() {
        for version in [61, 63, 64, 65] {
            let time = Time::default();
            let model = Model::nbase(&time);
            Model::store32(&mut model.state.borrow_mut(), TX_CONFIG, 0); // No old TXCFG_EMPTY condition.
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.initialize_modern().unwrap();
            let s = model.state.borrow();
            assert_eq!(s.mac[&0xc0aa], 0x7d0);
            assert_eq!(s.mac[&0xc0a6], 0x150);
            assert_eq!(s.mac[&0xc01e], 0x5555);
            assert!(time.now() >= 3700);
            assert_eq!(
                s.writes
                    .iter()
                    .any(|(r, v, _)| *r == COMMAND && *v & 0x80 != 0),
                version >= 63
            );
            drop(s);
            for broken in [MCU, INTERRUPT_MITIGATION, MAC_OCP] {
                if version == 61 && broken == INTERRUPT_MITIGATION {
                    continue;
                }
                let time = Time::default();
                let mut model = Model::nbase(&time);
                if broken == MCU {
                    model.state.borrow_mut().bytes[MCU] = 0x20;
                }
                if broken == INTERRUPT_MITIGATION {
                    model.state.borrow_mut().bytes[INTERRUPT_MITIGATION] = 0;
                }
                if broken == MAC_OCP {
                    model.shared_ready_delay = None;
                }
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.initialize_modern(), Err(BlockError::Timeout));
                assert!(
                    !model.state.borrow().writes.iter().any(|(r, _, _)| matches!(
                        *r,
                        PHY_OCP | TX_HIGH | TX_LOW | RX_HIGH | RX_LOW
                    ))
                );
            }
        }
    }

    #[test]
    fn nbase_a_b_phy_capability_internal_probe_tuning_and_advertisement_are_exact() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [61, 63] {
            for id in [0xc800, 0xc840] {
                let time = Time::default();
                let model = Model::nbase(&time);
                {
                    let mut s = model.state.borrow_mut();
                    s.phy_ocp.insert(0xa406, id);
                    s.phy_ocp.insert(NBASE_AN_CONTROL, 0xffff);
                    s.phy_ocp.insert(NBASE_EEE_ADV2, 0xffff);
                    s.n_parameters.insert(0x8551, 0xab);
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
                let s = model.state.borrow();
                assert_eq!(s.phy_ocp[&0xa400], 0x1200);
                assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL], 0xeeff);
                assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
                assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
                if version == 61 {
                    assert_eq!(s.n_parameters[&0x80a2], 0x153);
                    assert_eq!(s.n_parameters[&0x809c], 0x153);
                    assert_eq!(s.g_parameters[&0x8257], 0x20f);
                    assert_eq!(s.g_parameters[&0x80ea], 0x7843);
                    assert_eq!(
                        s.writes
                            .iter()
                            .filter(|(r, v, _)| *r == PHY_OCP && *v == 0xd21c_0000)
                            .count(),
                        25
                    );
                } else {
                    assert_eq!(s.n_parameters[&0x80f5], 0x760e);
                    assert_eq!(s.n_parameters[&0x8107], 0x360e);
                    assert_eq!(s.n_parameters[&0x8551], 0x08ab);
                    for address in [
                        0x8044, 0x804a, 0x8050, 0x8056, 0x805c, 0x8062, 0x8068, 0x806e, 0x8074,
                        0x807a,
                    ] {
                        assert_eq!(s.g_parameters[&address], 0x2417);
                    }
                }
            }
        }
        for version in [61, 63] {
            for rejected in 0..3 {
                let time = Time::default();
                let mut model = Model::nbase(&time);
                match rejected {
                    0 => {
                        model.state.borrow_mut().phy_ocp.insert(0xa616, 0x70);
                    }
                    1 => model.internal_nbase = false,
                    _ => {
                        model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc912);
                    }
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                assert!(matches!(
                    hw.configure_phy(Some(&script), false),
                    Err(Error::UnsupportedPhy(_))
                ));
                assert!(model.state.borrow().n_parameters.is_empty());
            }
        }
    }

    #[test]
    fn nbase_a_b_mac_selects_legacy_dma_and_preserves_distinct_masks_before_publish() {
        use crate::bus::dma::RegionAllocator;
        for version in [61, 63] {
            let time = Time::default();
            let model = Model::nbase(&time);
            {
                let mut s = model.state.borrow_mut();
                s.ephy.fill(0xa55a);
                s.mac.extend([
                    (0xeb58, 0xffff),
                    (0xe614, 0xffff),
                    (0xe63e, 0xffff),
                    (0xe040, 0xffff),
                    (0xeb62, 0xffff),
                ]);
            }
            let mut hw = Hardware::new(&model, &time, revision(version), 0);
            hw.initialize_modern().unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.mac[&0xeb58], 0xfffe);
                assert_eq!(s.mac[&0xe614], if version == 61 { 0xfbff } else { 0xfaff });
                assert_eq!(s.mac[&0xe63e], if version == 61 { 0xf3ef } else { 0xf3cf });
                assert_eq!(
                    u16::from_le_bytes(
                        s.bytes[NBASE_EEE_TXIDLE..NBASE_EEE_TXIDLE + 2]
                            .try_into()
                            .unwrap()
                    ),
                    1546
                );
                assert_eq!(
                    s.writes
                        .iter()
                        .filter(|(r, v, _)| *r == EPHY_ACCESS && *v & ACCESS != 0)
                        .count(),
                    if version == 61 { 12 } else { 6 }
                );
                if version == 61 {
                    assert_eq!(s.ephy[3], 0xab66);
                    assert_eq!(s.ephy[0], 0x9455);
                } else {
                    assert_eq!(s.ephy[2], 0xa56a);
                }
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing remains alive and has no other descriptor accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
            assert_eq!(
                model.read32(RX_CONFIG),
                (8 << 27) | (7 << 8) | 0xe | if version == 63 { 1 << 11 } else { 0 }
            );
            assert_eq!(model.read32(TX_CONFIG) & (1 << 7), 0);
        }
    }

    #[test]
    fn nbase_required_phy_and_mac_failures_abort_before_dma_for_both_ids() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [61, 63] {
            for id in [0xc800, 0xc840] {
                let time = Time::default();
                let model = Model::nbase(&time);
                model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                hw.configure_phy(Some(&script), false).unwrap();
                let total = model.state.borrow().phy_ocp_commands;
                for nth in [20, total / 2, total - 3] {
                    let time = Time::default();
                    let mut model = Model::nbase(&time);
                    model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                    model.fail_phy_ocp_at = nth;
                    let mut hw = Hardware::new(&model, &time, revision(version), 0);
                    assert_eq!(
                        hw.configure_phy(Some(&script), false),
                        Err(Error::Device(BlockError::Timeout))
                    );
                    assert_ne!(model.state.borrow().phy_ocp[&0xa400], 0x1200);
                    assert!(
                        !model
                            .state
                            .borrow()
                            .writes
                            .iter()
                            .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                    );
                }
            }
            for fault in 0..5 {
                let time = Time::default();
                let mut model = Model::nbase(&time);
                Model::store32(&mut model.state.borrow_mut(), MISC, RXDV_GATED);
                match fault {
                    0 => model.fault = Some(EPHY_ACCESS),
                    1 => model.fault = Some(CSI_ADDRESS),
                    2 => model.failed_read = Some(MAC_OCP),
                    3 => model.failed_read = Some(0x1880),
                    _ => {
                        model.state.borrow_mut().mac.insert(0xe00e, 1 << 13);
                    }
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 0);
                let expected = match fault {
                    2 => BlockError::Device { status: u32::MAX },
                    3 => BlockError::Device { status: 65535 },
                    _ => BlockError::Timeout,
                };
                assert_eq!(hw.configure_mac(None), Err(Error::Device(expected)));
                let s = model.state.borrow();
                assert_eq!(s.bytes[CONFIG_LOCK], 0);
                assert_ne!(Model::raw32(&s, MISC) & RXDV_GATED, 0);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
        }
    }

    #[test]
    fn nbase_backup_station_and_runtime_tx_lpi_failure_do_not_guess_recovery() {
        for version in [61, 63, 64, 65] {
            let time = Time::default();
            let model = Model::nbase(&time);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(read_station(&hw).unwrap(), Mac([2, 3, 4, 5, 6, 7]));
            {
                let mut s = model.state.borrow_mut();
                Model::store32(&mut s, NBASE_MAC0_BACKUP, 1);
                Model::store32(&mut s, MAC0, 0x1514_1312);
                Model::store32(&mut s, MAC4, 0x1716);
            }
            assert_eq!(
                read_station(&hw).unwrap(),
                Mac([0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
            );
            let mut model = Model::nbase(&time);
            model.failed_read = Some(NBASE_MAC0_BACKUP);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(
                read_station(&hw),
                Err(BlockError::Device { status: u32::MAX })
            );
            let mut model = Model::nbase(&time);
            model.fail_mac_address = Some(0xe040);
            model.state.borrow_mut().phy_ocp.insert(0xa402, 0x792d);
            let mut link = RuntimeLink::default();
            {
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(link.update(&hw), Err(BlockError::Device { status: 255 }));
            }
            let writes = model.state.borrow().writes.len();
            model.fail_mac_address = None;
            time.delay(50_000);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(link.update(&hw), Err(BlockError::Device { status: 255 }));
            assert_eq!(model.state.borrow().writes.len(), writes);
        }
    }

    #[test]
    fn nbase_polled_carrier_preserves_latch_low_an_restart_and_cache_expiry() {
        for version in [61, 63, 64, 65] {
            let time = Time::default();
            let model = Model::nbase(&time);
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.insert(0xa400, 0x1000);
                s.phy_ocp.insert(0xa402, 0x792d);
                s.bmsr_latch_low_once = true;
            }
            let hw = Hardware::new(&model, &time, revision(version), 0);
            let mut link = RuntimeLink::default();
            assert_eq!(link.update(&hw), Ok(true)); // Down state retries its low latch sample.
            assert_eq!(model.state.borrow().phy_ocp_commands, 3);
            let writes = model.state.borrow().writes.len();
            time.delay(NBASE_LINK_POLL_US - 1);
            assert_eq!(link.update(&hw), Ok(true));
            assert_eq!(model.state.borrow().writes.len(), writes);
            time.delay(1);
            assert_eq!(link.update(&hw), Ok(true));
            assert_eq!(model.state.borrow().phy_ocp_commands, 5);
            model.state.borrow_mut().bmsr_latch_low_once = true;
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Ok(false)); // Up state preserves the brief latched drop.
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Ok(true));
            model.state.borrow_mut().phy_ocp.insert(0xa400, 0x1200);
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Ok(false)); // Restart overrides an old link indication.
            {
                let mut s = model.state.borrow_mut();
                s.phy_ocp.insert(0xa400, 0x1000);
                s.phy_ocp.insert(0xa402, 0x790d);
            }
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Ok(false)); // AN not complete.
            model.state.borrow_mut().phy_ocp.insert(0xa402, u16::MAX);
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Err(BlockError::Device { status: 65535 }));
            let writes = model.state.borrow().writes.len();
            model.state.borrow_mut().phy_ocp.insert(0xa402, 0x792d);
            time.delay(NBASE_LINK_POLL_US);
            assert_eq!(link.update(&hw), Err(BlockError::Device { status: 65535 }));
            assert_eq!(model.state.borrow().writes.len(), writes);
            let mut model = Model::nbase(&time);
            model.fail_phy_ocp_at = 1;
            let mut link = RuntimeLink::default();
            {
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(link.update(&hw), Err(BlockError::Timeout));
            }
            let writes = model.state.borrow().writes.len();
            model.fail_phy_ocp_at = usize::MAX;
            time.delay(50_000);
            model.read32(PHY_OCP);
            let hw = Hardware::new(&model, &time, revision(version), 0);
            assert_eq!(link.update(&hw), Err(BlockError::Timeout));
            assert_eq!(model.state.borrow().writes.len(), writes);
        }
    }
    #[test]
    fn nbase_d_k_9151a_cp_exact_firmware_and_phy_paths_preserve_cp_only_effects() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for xid in [0x688, 0x689, 0x68a, 0x68b, 0x708] {
            let revision = revision::detect(xid << 20).unwrap();
            assert!(revision.implemented());
            assert!(revision::pci_family(0x8125, revision));
            assert!(!revision::pci_family(0x8126, revision));
            for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
                let time = Time::default();
                let model = Model::nbase(&time);
                {
                    let mut s = model.state.borrow_mut();
                    s.phy_ocp.extend([
                        (0xa406, id),
                        (0xa5b4, 0xffff),
                        (0xad0e, 0xa5ff),
                        (0xad78, 0x20),
                        (0xa430, 0x84),
                        (0xa442, 0x20),
                        (NBASE_AN_CONTROL, 0xffff),
                    ]);
                    s.n_parameters.insert(0x807f, 0x12a5);
                }
                let mut hw = Hardware::new(&model, &time, revision, 2);
                assert_eq!(hw.configure_phy(Some(&script), false).unwrap(), None);
                let s = model.state.borrow();
                assert_eq!(s.phy_ocp[&0xa5b4], 0x7fff);
                assert_eq!(s.phy_ocp[&0xa442] & 0x800, 0x800);
                assert_eq!(s.phy_ocp[&0xa430] & 4, 0);
                assert_eq!(s.phy_ocp[&0xa432] & 0x10, 0x10);
                assert_eq!(s.phy_ocp[&NBASE_AN_CONTROL], 0xeeff);
                assert_eq!(s.phy_ocp[&PHY_OCP_EEE_ADV], 0);
                assert_eq!(s.phy_ocp[&NBASE_EEE_ADV2], 0);
                assert_eq!(s.phy_ocp[&0xa400], 0x1200);
                let firmware = s
                    .writes
                    .iter()
                    .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd216_a55a)
                    .unwrap();
                let gphy = s
                    .writes
                    .iter()
                    .position(|(r, v, _)| *r == PHY_OCP && *v == 0xd221_0820)
                    .unwrap();
                assert!(firmware < gphy);
                if revision.version == 65 {
                    assert_eq!(s.phy_ocp[&0xad0e], 0xa58b);
                    assert_eq!(s.phy_ocp[&0xad78], 0x30);
                    assert_eq!(s.n_parameters[&0x807f], 0x53a5);
                    assert_eq!(s.phy_ocp[&0xa430] & 3, 3);
                    assert_eq!(s.phy_ocp[&0xa442] & 0x80, 0x80);
                    for (address, value) in [
                        (0x81b8, 0xb4),
                        (0x81ba, 0xe4),
                        (0x81c5, 0x104),
                        (0x81d0, 0x54d),
                    ] {
                        assert_eq!(s.g_parameters[&address], value);
                    }
                } else {
                    assert_eq!(s.phy_ocp[&0xad0e], 0xa5ff);
                    assert_eq!(s.phy_ocp[&0xad78], 0x20);
                    assert_eq!(s.n_parameters[&0x807f], 0x12a5);
                    assert!(s.g_parameters.is_empty());
                }
            }
        }
    }

    #[test]
    fn nbase_d_cp_id_capability_external_and_required_firmware_failures_are_explicit() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [64, 65] {
            for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
                for rejected in 0..4 {
                    let time = Time::default();
                    let mut model = Model::nbase(&time);
                    model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                    match rejected {
                        0 => {
                            model.state.borrow_mut().phy_ocp.insert(0xa616, 0x70);
                        }
                        1 => model.internal_nbase = false,
                        2 => {
                            model.state.borrow_mut().phy_ocp.insert(0xa406, 0xc861);
                        }
                        _ => {}
                    }
                    let mut hw = Hardware::new(&model, &time, revision(version), 0);
                    let result = hw.configure_phy((rejected != 3).then_some(&script), false);
                    assert!(matches!(
                        result,
                        Err(Error::UnsupportedPhy(_)) | Err(Error::Script(_))
                    ));
                    let s = model.state.borrow();
                    assert!(s.n_parameters.is_empty());
                    assert!(s.g_parameters.is_empty());
                    assert!(
                        !s.writes
                            .iter()
                            .any(|(r, v, _)| (*r == PHY_OCP && *v == 0xd216_a55a)
                                || matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                    );
                }
            }
        }
    }

    #[test]
    fn nbase_d_cp_required_command_failures_abort_before_enable_or_dma() {
        let bytes = 0x8016_a55au32.to_le_bytes();
        let script = Script::parse(&bytes).unwrap();
        for version in [64, 65] {
            for id in [0xc800, 0xc840, 0xc841, 0xc862, 0xc890] {
                let time = Time::default();
                let model = Model::nbase(&time);
                model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                Hardware::new(&model, &time, revision(version), 0)
                    .configure_phy(Some(&script), false)
                    .unwrap();
                let total = model.state.borrow().phy_ocp_commands;
                for nth in [20, total / 2, total - 3] {
                    let time = Time::default();
                    let mut model = Model::nbase(&time);
                    model.state.borrow_mut().phy_ocp.insert(0xa406, id);
                    model.fail_phy_ocp_at = nth;
                    let mut hw = Hardware::new(&model, &time, revision(version), 0);
                    assert_eq!(
                        hw.configure_phy(Some(&script), false),
                        Err(Error::Device(BlockError::Timeout))
                    );
                    let s = model.state.borrow();
                    assert_ne!(s.phy_ocp[&0xa400], 0x1200);
                    assert!(
                        !s.writes
                            .iter()
                            .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                    );
                }
            }
            for fault in 0..4 {
                let time = Time::default();
                let mut model = Model::nbase(&time);
                Model::store32(&mut model.state.borrow_mut(), MISC, RXDV_GATED);
                match fault {
                    0 => model.fault = Some(CSI_ADDRESS),
                    1 => model.failed_read = Some(MAC_OCP),
                    2 => model.failed_read = Some(0x1880),
                    _ => {
                        model.state.borrow_mut().mac.insert(0xe00e, 1 << 13);
                    }
                }
                let mut hw = Hardware::new(&model, &time, revision(version), 2);
                assert!(hw.configure_mac(None).is_err());
                let s = model.state.borrow();
                assert_eq!(s.bytes[CONFIG_LOCK], 0);
                assert_ne!(Model::raw32(&s, MISC) & RXDV_GATED, 0);
                assert!(
                    !s.writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
        }
    }

    #[test]
    fn nbase_d_cp_mac_has_no_ephy_table_and_publishes_source_rx_and_legacy_dma() {
        use crate::bus::dma::RegionAllocator;
        for xid in [0x688, 0x689, 0x68a, 0x68b, 0x708] {
            let revision = revision::detect(xid << 20).unwrap();
            let time = Time::default();
            let model = Model::nbase(&time);
            {
                let mut s = model.state.borrow_mut();
                s.mac
                    .extend([(0xeb58, 0xffff), (0xe614, 0xffff), (0xe63e, 0xffff)]);
                s.ephy.fill(0xa55a);
            }
            let mut hw = Hardware::new(&model, &time, revision, 2);
            hw.initialize_modern().unwrap();
            hw.configure_mac(None).unwrap();
            {
                let s = model.state.borrow();
                assert_eq!(s.mac[&0xeb58], 0xfffe);
                assert_eq!(s.mac[&0xe614], 0xfbff);
                assert_eq!(s.mac[&0xe63e], 0xf3ef);
                assert!(s.ephy.iter().all(|v| *v == 0xa55a));
                assert!(!s.writes.iter().any(|(r, _, _)| *r == EPHY_ACCESS));
                assert!(s.writes.contains(&(0xafc, 0, 4)));
                assert!(!s.writes.iter().any(|(r, _, _)| *r == 0x7a));
                assert!(s.writes.contains(&(CSI_ADDRESS, 0x0002_f70c, 4)));
            }
            let mut backing = vec![0u64; 40_000];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives both rings and has no other accesses.
            let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            let mut rx = Ring::new(&mut dma, true).unwrap();
            let mut tx = Ring::new(&mut dma, true).unwrap();
            rx.initialize(true);
            tx.initialize(false);
            publish(&hw, &rx, &tx, read_station(&hw).unwrap()).unwrap();
            assert_eq!(
                model.read32(RX_CONFIG),
                (8 << 27) | (7 << 8) | (1 << 11) | 0xe
            );
            assert_eq!(model.read32(TX_CONFIG) & (1 << 7), 0);
        }
    }
}
