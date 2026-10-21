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
//! 17..26 (8168B/C/CP/D, 8111B/C/CP/D), 34..36 (8168E-VL/F,
//! 8111E-VL/F) and 38 (RTL8411). PHY IDs
//! `001c:c800` (internal FE/GE) and `001c:c912` (RTL8211B) are accepted only
//! with actual copper-gigabit capabilities. Versions 25/26 require their exact
//! `rtl_nic/rtl8168d-1.fw`/`rtl_nic/rtl8168d-2.fw` resource and matching PHY
//! firmware-readiness sentinel; 34 requires `rtl_nic/rtl8168e-3.fw`.
//! Versions 35/36/38 require their exact F/8411 firmware and the internal
//! FE/GE PHY; external PHY initialization is outside these new paths.
//! No firmware bytes are embedded or copied.
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
        let mac = read_station(&hardware)?;
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
        if self.link_status != Some(status)
            && status & 2 != 0
            && matches!(self.revision.version, 34..=36 | 38)
        {
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
    if matches!(hw.revision.version, 35 | 36 | 38)
        && let Some(mac) = station(hw.eri_read(0xe0)?, hw.eri_read(0xe4)?)
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
        25 | 26 => (1 << 15) | (7 << 8),
        _ => (1 << 15) | (1 << 14) | (7 << 8),
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
        mac: BTreeMap<u16, u16>,
        page: u16,
        parameter: u16,
        parameters: BTreeMap<u16, u16>,
        efuse: u8,
        extended_page: u16,
        extended: BTreeMap<(u16, u16), u16>,
        pending: Option<(usize, u32, u64)>,
        reset_phy_at: Option<u64>,
        reset_mac_at: Option<u64>,
        writes: Vec<(usize, u32, u8)>,
        mdio_commands: usize,
    }
    struct Model {
        state: RefCell<State>,
        time: Time,
        fault: Option<usize>,
        failed_read: Option<usize>,
        fail_phy_at: usize,
        stuck_reset: bool,
        stuck_phy_reset: bool,
        command_readback: Option<u8>,
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
                stuck_reset: false,
                stuck_phy_reset: false,
                command_readback: None,
            }
        }
        fn raw32(s: &State, o: usize) -> u32 {
            u32::from_le_bytes(s.bytes[o..o + 4].try_into().unwrap())
        }
        fn store32(s: &mut State, o: usize, v: u32) {
            s.bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn complete(&self, s: &mut State) {
            if s.reset_phy_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_phy_reset {
                s.phy.entry((0, 0)).and_modify(|v| *v &= !PHY_RESET);
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
                    if write {
                        let mut value = *s.eri.get(&reg).unwrap_or(&0);
                        let data = Self::raw32(s, ERI_DATA);
                        for byte in 0..4 {
                            if command & (1 << (12 + byte)) != 0 {
                                value =
                                    (value & !(0xff << (byte * 8))) | (data & (0xff << (byte * 8)));
                            }
                        }
                        s.eri.insert(reg, value);
                        command & !ACCESS
                    } else {
                        Self::store32(s, ERI_DATA, *s.eri.get(&reg).unwrap_or(&0));
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
                PHY_OCP => {
                    if write {
                        command & !ACCESS
                    } else {
                        command | ACCESS | 0x1234
                    }
                }
                _ => panic!("unmodeled command port"),
            };
            Self::store32(s, port, value);
        }
    }
    impl Registers for Model {
        fn read8(&self, o: usize) -> u8 {
            let mut s = self.state.borrow_mut();
            self.complete(&mut s);
            if o == COMMAND && s.bytes[o] == ENABLE {
                return self.command_readback.unwrap_or(s.bytes[o]);
            }
            s.bytes[o]
        }
        fn read16(&self, o: usize) -> u16 {
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
            s.bytes[o] = v;
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
                PHY_ACCESS | EPHY_ACCESS | ERI_ADDRESS | CSI_ADDRESS | PHY_OCP | EFUSE_ACCESS
            ) {
                if o == PHY_ACCESS {
                    s.mdio_commands += 1;
                }
                s.pending = Some((o, v, self.time.now() + 15));
            }
            if o == MAC_OCP {
                let reg = ((v & !ACCESS) >> 15) as u16;
                if v & ACCESS != 0 {
                    s.mac.insert(reg, v as u16);
                } else {
                    let data = u32::from(*s.mac.get(&reg).unwrap_or(&0));
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
            32 => 0x2c1,
            33 => 0x2c0,
            35 => 0x480,
            36 => 0x481,
            38 => 0x488,
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
            (0x649, 70, Some("rtl_nic/rtl8126a-2.fw")),
            (0x64a, 70, Some("rtl_nic/rtl8126a-3.fw")),
            (0x980, 6, None),
        ] {
            let r = revision::detect(xid << 20).unwrap();
            assert_eq!((r.version, r.firmware), (version, fw));
            assert_eq!(u32::from(r.xid), xid);
            if version >= 61 {
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
            let hw = Hardware::new(&model, &time, revision(34), 3);
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
                assert_eq!(hw.configure_mac(), Err(BlockError::Timeout));
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
            let hw = Hardware::new(&model, &time, revision(version), 2);
            hw.reset().unwrap();
            hw.configure_mac().unwrap();
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
                assert_eq!(result, Ok(()));
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
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_mac().unwrap();
            assert_eq!(model.read8(CONFIG3) & 4, 0);
            assert_eq!(model.read8(CONFIG4) & 2, 0);
            assert_eq!(model.read8(CONFIG_LOCK), 0);
            publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
            assert_eq!(model.read32(RX_CONFIG), (1 << 15) | (7 << 8) | 0x0e);
        }
        for xid in [0x28a, 0x28b, 0x2c1, 0x2c0, 0x4c0, 0x609, 0x64a] {
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
            let hw = Hardware::new(&model, &time, revision(version), 0);
            hw.configure_mac().unwrap();
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
                let hw = Hardware::new(&model, &time, revision(version), 0);
                assert_eq!(hw.configure_mac(), Err(BlockError::Timeout));
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
}
