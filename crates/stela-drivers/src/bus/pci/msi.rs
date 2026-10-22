// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig.
// Copyright (c) 2026 Stela contributors
//! Single-message PCI MSI configuration with retained real config ownership.
//! Register layouts and narrow message programming follow Linux PCI MSI at
//! a804c5742bff224d4cb4d25dd383554d598be32b. Ownership, validation, readback and
//! quarantine are Stela integration. This is not an IRQ controller or DMA stop.
use super::{Address, ConfigSpace, EcamConfig, Function};
use crate::bus::irq::MsiMessage;
use alloc::sync::Arc;
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};

const COMMAND: u16 = 4;
const STATUS: u16 = 6;
const INTX_DISABLE: u16 = 1 << 10;
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

/// A transport whose `write16` has the actual native word-store effect.
///
/// # Safety
/// Configuration reads/writes have real serialized effects. In particular,
/// `write16` never replays adjacent Status W1C bits through a dword RMW. It
/// must override the generic model fallback. Access remains valid under the
/// enclosing actual owner and occurs only in process/deferred context.
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
    fn end(self) -> u16 {
        self.offset
            + match (self.wide(), self.mask().is_some()) {
                (false, false) => 10,
                (true, false) => 14,
                (false, true) => 20,
                (true, true) => 24,
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

/// Full standard extents from the pinned pci_regs.h. Unknown capability
/// formats still reserve their two-byte headers; no body length is invented.
fn other_capability_bytes<C: MsiConfigSpace>(
    c: &C,
    offset: u16,
    id: u8,
    header_type: u8,
) -> Result<u16, MsiError> {
    Ok(match id {
        0x01 => 8,  // PCI_PM_SIZEOF, including PPB extensions/data.
        0x02 => 12, // PCI_AGP_SIZEOF.
        0x03 => 8,  // PCI_CAP_VPD_SIZEOF.
        0x04 => 4,  // Slot identification ESR + chassis number.
        0x0d => 8,  // Bridge subsystem vendor/device IDs at offsets 4/6.
        0x13 => 6,  // PCI_CAP_AF_SIZEOF.
        0x09 => {
            // Vendor-specific capability byte two is its declared total size.
            let bytes = u16::from(c.read8(offset + 2));
            if bytes < 3 {
                return Err(MsiError::MalformedCapability);
            }
            bytes
        }
        0x07 => {
            // Pinned PCI-X endpoint sizes; bridge extended layout is separate.
            if header_type != 0 {
                return Err(MsiError::Unsupported);
            }
            match (read16(c, offset + 2)? >> 12) & 3 {
                0 => 8,
                1 | 2 => 24,
                _ => return Err(MsiError::Unsupported),
            }
        }
        0x10 => {
            let flags = read16(c, offset + 2)?;
            // Exact endpoint layouts from PCI_CAP_EXP_*_SIZEOF_V1/V2.
            // Ports/bridges/collectors and unknown versions need their actual
            // conditional slot/root layout, never an assumed endpoint size.
            if flags & 0x100 != 0 {
                return Err(MsiError::Unsupported);
            }
            match (flags & 15, (flags >> 4) & 15) {
                (1, 0 | 1) => 20,
                (1, 9) => 12,
                (2, 0 | 1) => 0x34,
                (2, 9) => 0x2c,
                _ => return Err(MsiError::Unsupported),
            }
        }
        0x12 => {
            if offset + 8 > 256 {
                return Err(MsiError::MalformedCapability);
            }
            match read16(c, offset + 4)? & 15 {
                0..=5 => 8,
                15 => 16,
                _ => return Err(MsiError::Unsupported),
            }
        } // PCI_SATA_SIZEOF_SHORT/LONG, BAR or inline register block.
        _ => 2,
    })
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
    if read16(c, STATUS)? & CAP_LIST == 0 {
        return Err(MsiError::MissingCapability);
    }
    let mut offset = u16::from(c.read8(0x34));
    let mut occupied = [false; 256];
    let mut found = None;
    let mut msix = None;
    while offset != 0 {
        if !(0x40..=0xfc).contains(&offset)
            || !offset.is_multiple_of(4)
            || occupied[usize::from(offset)..usize::from(offset + 2)]
                .iter()
                .any(|v| *v)
        {
            return Err(MsiError::MalformedCapability);
        }
        let header = read16(c, offset)?;
        let bytes = match header as u8 {
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
                    header,
                    features: control & !(ENABLE | MME),
                };
                if layout.end() > 256 {
                    return Err(MsiError::MalformedCapability);
                }
                found = Some((layout, control));
                layout.end() - offset
            }
            MSIX => {
                if msix.replace(()).is_some() {
                    return Err(MsiError::MalformedCapability);
                }
                if offset + 12 > 256 {
                    return Err(MsiError::MalformedCapability);
                }
                if read16(c, offset + 2)? & MSIX_ENABLE != 0 {
                    return Err(MsiError::ActiveMsix);
                }
                12
            }
            0 | 0xff => return Err(MsiError::MalformedCapability),
            id => other_capability_bytes(c, offset, id, header_type)?,
        };
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= 256)
            .ok_or(MsiError::MalformedCapability)?;
        let extent = &mut occupied[usize::from(offset)..usize::from(end)];
        if extent.iter().any(|v| *v) {
            return Err(MsiError::MalformedCapability);
        }
        extent.fill(true);
        offset = header >> 8;
    }
    found.ok_or(MsiError::MissingCapability)
}

/// Owns the original Function and actual retained PCI/config/root/reset epoch.
/// There is no raw config escape or second enumeration. No method changes BM,
/// acknowledges a device cause, drains callbacks, or infers DMA coherency.
/// Operations and final release require process/deferred context, never an ISR.
pub struct MsiConfig<C: MsiConfigSpace = EcamConfig> {
    owner: Option<Released<C>>,
    layout: Layout,
    message: Option<MsiMessage>,
}
impl<C: MsiConfigSpace> MsiConfig<C> {
    /// # Safety
    /// `function` is the actual unique function (unmodified identity/address),
    /// and `retained` is its genuine config/root/PCI/reset-epoch owner, not a
    /// dummy token. This retains the real mapped configuration transport even
    /// if abandoned. Native config accesses and every source/worker/reset are
    /// serialized; no firmware/alias/other CPU can reconfigure or revoke it.
    /// Old MSI/INTx delivery, callbacks and device work have actually drained;
    /// initially disabled MSI alone does not establish this. The platform has
    /// qualified MSI routing. No vector or requester-coherency grant is created.
    /// Errors return both actual owners without modifying configuration.
    pub unsafe fn new(
        mut function: Function<C>,
        retained: RetainedOwner,
    ) -> Result<Self, (MsiError, Released<C>)> {
        match discover(&mut function) {
            Ok((layout, control)) if control & ENABLE == 0 => Ok(Self {
                owner: Some((function, retained)),
                layout,
                message: None,
            }),
            Ok(_) => Err((MsiError::ActiveMsi, (function, retained))),
            Err(error) => Err((error, (function, retained))),
        }
    }
    pub fn address(&self) -> Result<Address, MsiError> {
        Ok(self.owner.as_ref().ok_or(MsiError::Released)?.0.address)
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
            // All-ones is a valid mask bitmap. Presence/control reads qualify
            // this transport; never interpret valid all-masked as failed data.
            write32(c, offset, mask | 1)?;
        }
        write16(c, layout.offset + 2, control & !ENABLE)
    }
    /// Mask and acknowledge MSI plus fallback INTx. This does not stop a device
    /// or drain already posted writes, callbacks, timers or deferred work.
    pub fn mask(&mut self) -> Result<(), MsiError> {
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
    /// This typed message belongs to the actual registry's qualified route;
    /// every callback/resource remains retained. Reprogramming requires real
    /// source/callback/posted-write drain; masking alone is insufficient.
    pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), MsiError> {
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
    /// The actual registry retains/publishes the callback and qualified route;
    /// the requester and all IRQ/DMA/work/reset owners remain retained. BM and
    /// vendor source enable are separately controlled by that owner.
    pub unsafe fn unmask(&mut self) -> Result<(), MsiError> {
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
    /// Return the exact owners only after independent source/IRQ/work drain.
    ///
    /// # Safety
    /// The actual device is stopped, posted MSI writes/CPU pending vectors,
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
            // No hardware access or guessed completion in Drop. Retain the
            // real configuration and root owner on every uncertain path.
            core::mem::forget(owner);
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
        }
    }
}
/// Cumulative abandoned config/root owners, deliberately retained for safety.
pub fn quarantined_configurations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Read(u16, u8),
        Write(u16, u8, u32),
    }
    struct Model {
        bytes: [u8; 256],
        events: Vec<Event>,
        fail_read: Option<(u16, u8)>,
        block_write: Option<(u16, u8)>,
        fail_enable_ack: bool,
    }
    impl Model {
        fn get(&self, offset: u16, width: u8) -> u32 {
            let mut word = [0; 4];
            word[..usize::from(width)].copy_from_slice(
                &self.bytes[usize::from(offset)..usize::from(offset + u16::from(width))],
            );
            u32::from_le_bytes(word)
        }
        fn put(&mut self, offset: u16, width: u8, value: u32) {
            self.bytes[usize::from(offset)..usize::from(offset + u16::from(width))]
                .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        }
    }
    struct Config {
        model: Arc<Mutex<Model>>,
        dropped: Arc<AtomicU64>,
    }
    impl Config {
        fn read(&self, offset: u16, width: u8) -> u32 {
            let mut m = self.model.lock().unwrap();
            m.events.push(Event::Read(offset, width));
            if m.fail_read == Some((offset, width)) {
                return if width == 2 {
                    u32::from(u16::MAX)
                } else {
                    u32::MAX
                };
            }
            m.get(offset, width)
        }
        fn write(&mut self, offset: u16, width: u8, value: u32) {
            assert!(
                !(offset == COMMAND && width == 4),
                "dword Command RMW would replay adjacent Status W1C"
            );
            let mut m = self.model.lock().unwrap();
            m.events.push(Event::Write(offset, width, value));
            if m.block_write != Some((offset, width)) {
                m.put(offset, width, value);
                if m.fail_enable_ack && offset == 0x52 && value & 1 != 0 {
                    m.fail_read = Some((0x52, 2));
                }
            }
        }
    }
    impl Drop for Config {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.read(offset, 4)
        }
        fn read16(&self, offset: u16) -> u16 {
            self.read(offset, 2) as u16
        }
        fn read8(&self, offset: u16) -> u8 {
            self.model.lock().unwrap().get(offset, 1) as u8
        }
        fn write32(&mut self, offset: u16, value: u32) {
            self.write(offset, 4, value);
        }
        fn write16(&mut self, offset: u16, value: u16) {
            self.write(offset, 2, u32::from(value));
        }
    }
    // SAFETY: trace model implements genuine word writes without dword RMW.
    unsafe impl MsiConfigSpace for Config {}
    struct Root(Arc<AtomicU64>);
    impl Drop for Root {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Fixture {
        function: Function<Config>,
        model: Arc<Mutex<Model>>,
        config_drops: Arc<AtomicU64>,
        root: RetainedOwner,
        root_drops: Arc<AtomicU64>,
    }
    fn fixture(wide: bool, mask: bool) -> Fixture {
        let mut model = Model {
            bytes: [0; 256],
            events: Vec::new(),
            fail_read: None,
            block_write: None,
            fail_enable_ack: false,
        };
        model.put(0, 4, 0x1234_8086);
        model.put(COMMAND, 2, 0x107); // BM, IO, memory and unrelated SERR bit.
        model.put(STATUS, 2, 0xa510); // includes live W1C bits and CapList.
        model.put(0x34, 1, 0x50);
        model.put(0x50, 2, u32::from(MSI));
        model.put(
            0x52,
            2,
            u32::from(
                (if wide { WIDE } else { 0 })
                    | (if mask { MASK_CAPABLE } else { 0 })
                    | 5 << 1
                    | 5 << 4,
            ),
        );
        if mask {
            model.put(if wide { 0x60 } else { 0x5c }, 4, 0xa5a5_0002);
        }
        model.put(if wide { 0x5e } else { 0x5a }, 2, 0x5a5a); // neighboring data padding.
        let model = Arc::new(Mutex::new(model));
        let config_drops = Arc::new(AtomicU64::new(0));
        let root_drops = Arc::new(AtomicU64::new(0));
        let function = Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 2,
                function: 0,
            },
            Config {
                model: model.clone(),
                dropped: config_drops.clone(),
            },
        )
        .unwrap();
        Fixture {
            function,
            model,
            config_drops,
            root: Arc::new(Root(root_drops.clone())),
            root_drops,
        }
    }
    fn attach(f: Fixture) -> (MsiConfig<Config>, Arc<Mutex<Model>>) {
        let model = f.model;
        // SAFETY: unique stopped model function and actual retained model root.
        let helper = match unsafe { MsiConfig::new(f.function, f.root) } {
            Ok(helper) => helper,
            Err((e, _)) => panic!("attach {e:?}"),
        };
        model.lock().unwrap().events.clear();
        (helper, model)
    }
    const MESSAGE: MsiMessage = MsiMessage {
        address: 0xfee0_1000,
        data: 0x51,
    };

    #[test]
    fn real_layouts_program_while_disabled_with_narrow_writes_and_preserved_bits() {
        for wide in [false, true] {
            for mask in [false, true] {
                let (mut helper, model) = attach(fixture(wide, mask));
                let message = if wide {
                    MsiMessage {
                        address: 0x1234_5678_fee0_1000,
                        ..MESSAGE
                    }
                } else {
                    MESSAGE
                };
                // SAFETY: qualified model registry route; no source in flight.
                unsafe { helper.program(message) }.unwrap();
                {
                    let m = model.lock().unwrap();
                    let writes: Vec<_> = m
                        .events
                        .iter()
                        .filter_map(|e| {
                            if let Event::Write(o, w, v) = e {
                                Some((*o, *w, *v))
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert_eq!(writes[0], (COMMAND, 2, 0x507));
                    let disabled = writes
                        .iter()
                        .position(|(o, w, v)| *o == 0x52 && *w == 2 && v & u32::from(ENABLE) == 0)
                        .unwrap();
                    let address = writes.iter().position(|(o, _, _)| *o == 0x54).unwrap();
                    assert!(disabled < address);
                    assert_eq!(m.get(STATUS, 2), 0xa510);
                    assert_eq!(m.get(0x52, 2) & u32::from(ENABLE | MME), 0);
                    assert_eq!(m.get(0x52, 2) & u32::from(MMC), 5 << 1);
                    assert_eq!(m.get(0x54, 4), message.address as u32);
                    if wide {
                        assert_eq!(m.get(0x58, 4), (message.address >> 32) as u32);
                    }
                    assert_eq!(m.get(if wide { 0x5c } else { 0x58 }, 2), message.data);
                    assert_eq!(m.get(if wide { 0x5e } else { 0x5a }, 2), 0x5a5a);
                    if mask {
                        assert_eq!(m.get(if wide { 0x60 } else { 0x5c }, 4), 0xa5a5_0003);
                    }
                }
                // SAFETY: model callback published, all actual owners retained.
                unsafe { helper.unmask() }.unwrap();
                {
                    let m = model.lock().unwrap();
                    assert_eq!(m.get(0x52, 2) & u32::from(ENABLE | MME), 1);
                    if mask {
                        assert_eq!(m.get(if wide { 0x60 } else { 0x5c }, 4), 0xa5a5_0002);
                    }
                }
                helper.mask().unwrap();
                unsafe { helper.unmask() }.unwrap();
                helper.disable().unwrap();
                assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
                // SAFETY: independent model source/CPU callbacks have drained.
                let (function, root) = unsafe { helper.release() }.unwrap();
                assert_eq!(function.address.device, 2);
                drop((function, root));
                assert_eq!(helper.mask(), Err(MsiError::Released));
            }
        }
    }
    #[test]
    fn malformed_duplicate_overlapping_or_live_capabilities_are_refused_without_writes() {
        for case in 0..11 {
            let f = fixture(false, false);
            let expected = {
                let mut m = f.model.lock().unwrap();
                match case {
                    0 => {
                        m.put(0x34, 1, 0x51);
                        MsiError::MalformedCapability
                    }
                    1 => {
                        m.put(0x50, 2, 0x5005);
                        MsiError::MalformedCapability
                    }
                    2 => {
                        m.put(0x50, 2, 0x7005);
                        m.put(0x70, 2, 5);
                        MsiError::MalformedCapability
                    }
                    3 => {
                        m.put(0x34, 1, 0xfc);
                        m.put(0xfc, 2, 5);
                        MsiError::MalformedCapability
                    }
                    4 => {
                        m.put(0x50, 2, 0x5805);
                        m.put(0x58, 2, 0x10);
                        MsiError::MalformedCapability
                    }
                    5 => {
                        m.put(0x52, 2, 12);
                        MsiError::Unsupported
                    }
                    6 => {
                        m.put(0x52, 2, 1 << 4);
                        MsiError::Unsupported
                    }
                    7 => {
                        m.put(0x52, 2, 1);
                        MsiError::ActiveMsi
                    }
                    8 => {
                        m.put(0x50, 2, 0x8005);
                        m.put(0x80, 2, 0x11);
                        m.put(0x82, 2, 0x8000);
                        MsiError::ActiveMsix
                    }
                    10 => {
                        m.put(0x34, 1, 0x48);
                        m.put(0x48, 2, 0x5011);
                        MsiError::MalformedCapability
                    }
                    _ => {
                        m.put(0x52, 2, 1 << 9);
                        MsiError::Unsupported
                    }
                }
            };
            let result = unsafe { MsiConfig::new(f.function, f.root) };
            let (e, (function, root)) = match result {
                Err(e) => e,
                Ok(_) => panic!("accepted case {case}"),
            };
            assert_eq!(e, expected, "case {case}");
            assert!(
                !f.model
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Write(..)))
            );
            drop((function, root));
            assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
            assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn pm_body_cannot_alias_msi_in_either_list_order_before_any_write() {
        for reverse in [false, true] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                // Exact review repro: fake MSI54 aliases real PM50's PMCSR,
                // PPB extensions/data. Old program changed word56 0x5a→0x0a.
                m.bytes.copy_within(0x50..0x5a, 0x54);
                m.put(0x34, 1, if reverse { 0x54 } else { 0x50 });
                m.put(0x50, 2, if reverse { 1 } else { 0x5401 });
                m.put(0x52, 2, 3);
                m.put(0x54, 2, if reverse { 0x5005 } else { 5 });
                assert_eq!(m.get(0x56, 2), 0x5a);
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("PM body admitted as MSI"),
            };
            assert_eq!(error, MsiError::MalformedCapability);
            let m = f.model.lock().unwrap();
            assert_eq!(m.get(0x56, 2), 0x5a);
            assert!(!m.events.iter().any(|e| matches!(e, Event::Write(..))));
            drop(owners);
        }
    }
    #[test]
    fn known_extents_and_unknown_headers_reject_bidirectional_aliases() {
        // All these known bodies can contain an aligned fake MSI header.
        for (id, flags) in [
            (1u8, 3),
            (2, 0),
            (3, 0),
            (7, 0),
            (7, 0x1000),
            (9, 8),
            (0x0d, 0),
            (0x10, 1),
            (0x10, 2),
            (0x10, 0x91),
            (0x10, 0x92),
            (0x12, 0),
            (0x13, 0),
        ] {
            for reverse in [false, true] {
                let f = fixture(false, false);
                {
                    let mut m = f.model.lock().unwrap();
                    m.bytes.copy_within(0x50..0x5a, 0x54);
                    m.put(0x34, 1, if reverse { 0x54 } else { 0x50 });
                    m.put(0x50, 2, u32::from(id) | if reverse { 0 } else { 0x5400 });
                    m.put(0x52, 2, flags);
                    m.put(0x54, 2, if reverse { 0x5005 } else { 5 });
                }
                let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                    Err(e) => e,
                    Ok(_) => panic!("body alias admitted id={id:#x} reverse={reverse}"),
                };
                assert_eq!(
                    error,
                    MsiError::MalformedCapability,
                    "id={id:#x} reverse={reverse}"
                );
                assert!(
                    !f.model
                        .lock()
                        .unwrap()
                        .events
                        .iter()
                        .any(|e| matches!(e, Event::Write(..)))
                );
                drop(owners);
            }
        }
        // Unknown two-byte headers remain occupied even inside MSI data or
        // either actual per-vector Pending bitmap, in either list order.
        for (wide, mask, header) in [
            (false, false, 0x58),
            (false, true, 0x60),
            (true, true, 0x64),
        ] {
            for reverse in [false, true] {
                let f = fixture(wide, mask);
                {
                    let mut m = f.model.lock().unwrap();
                    m.put(0x34, 1, if reverse { header } else { 0x50 });
                    m.put(0x50, 2, if reverse { 5 } else { (header << 8) | 5 });
                    m.put(header as u16, 2, if reverse { 0x507e } else { 0x007e });
                }
                let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                    Err(e) => e,
                    Ok(_) => panic!("unknown header in MSI data/Pending body admitted"),
                };
                assert_eq!(error, MsiError::MalformedCapability);
                assert!(
                    !f.model
                        .lock()
                        .unwrap()
                        .events
                        .iter()
                        .any(|e| matches!(e, Event::Write(..)))
                );
                drop(owners);
            }
        }
    }
    #[test]
    fn overlapping_non_msi_bodies_also_refuse_before_any_mutation() {
        for reverse in [false, true] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                m.bytes.copy_within(0x50..0x5a, 0x70);
                m.put(0x34, 1, if reverse { 0x44 } else { 0x40 });
                m.put(0x40, 2, if reverse { 0x7001 } else { 0x4401 });
                m.put(0x42, 2, 3);
                m.put(0x44, 2, if reverse { 0x4003 } else { 0x7003 });
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("PM/VPD body overlap admitted"),
            };
            assert_eq!(error, MsiError::MalformedCapability);
            assert!(
                !f.model
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Write(..)))
            );
            drop(owners);
        }
    }
    #[test]
    fn supported_standard_extents_can_precede_a_disjoint_real_msi() {
        for (id, flags, registers) in [
            (1u8, 3, 0),
            (2, 0, 0),
            (3, 0, 0),
            (4, 0, 0),
            (7, 0, 0),
            (7, 0x1000, 0),
            (7, 0x2000, 0),
            (9, 8, 0),
            (0x0d, 0, 0),
            (0x10, 1, 0),
            (0x10, 2, 0),
            (0x10, 0x91, 0),
            (0x10, 0x92, 0),
            (0x12, 0, 0),
            (0x12, 0, 15),
            (0x13, 0, 0),
            (0x7e, 0, 0),
        ] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                m.bytes.copy_within(0x50..0x5a, 0xc0);
                m.put(0x34, 1, 0x40);
                m.put(0x40, 2, 0xc000 | u32::from(id));
                m.put(0x42, 2, flags);
                m.put(0x44, 2, registers);
            }
            let (mut helper, _) = attach(f);
            unsafe { helper.program(MESSAGE) }.unwrap();
            drop(unsafe { helper.release() }.unwrap());
        }
    }
    #[test]
    fn adjacent_disjoint_capabilities_remain_valid_and_unknown_versions_refuse() {
        for reverse in [false, true] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                m.put(0x34, 1, if reverse { 0x50 } else { 0x48 });
                m.put(0x48, 2, if reverse { 1 } else { 0x5001 });
                m.put(0x4a, 2, 3);
                m.put(0x50, 2, if reverse { 0x4805 } else { 5 });
            }
            let (mut helper, model) = attach(f);
            unsafe { helper.program(MESSAGE) }.unwrap();
            assert_eq!(model.lock().unwrap().get(0x4a, 2), 3);
            drop(unsafe { helper.release() }.unwrap());
        }
        for (id, flags) in [
            (7, 0x3000),
            (0x10, 0),
            (0x10, 3),
            (0x10, 0x42),
            (0x10, 0x102),
        ] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                m.put(0x34, 1, 0x40);
                m.put(0x40, 2, 0x5000 | id);
                m.put(0x42, 2, flags);
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("unknown capability format guessed"),
            };
            assert_eq!(error, MsiError::Unsupported);
            assert!(
                !f.model
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Write(..)))
            );
            drop(owners);
        }
    }
    #[test]
    fn valid_all_masked_bitmap_preserves_every_other_vector_bit() {
        let f = fixture(true, true);
        f.model.lock().unwrap().put(0x60, 4, u32::MAX);
        let (mut helper, model) = attach(f);
        unsafe { helper.program(MESSAGE) }.unwrap();
        assert_eq!(model.lock().unwrap().get(0x60, 4), u32::MAX);
        unsafe { helper.unmask() }.unwrap();
        assert_eq!(model.lock().unwrap().get(0x60, 4), !1u32);
        helper.mask().unwrap();
        assert_eq!(model.lock().unwrap().get(0x60, 4), u32::MAX);
        drop(unsafe { helper.release() }.unwrap());
    }
    #[test]
    fn invalid_messages_and_unprogrammed_unmask_never_enable_delivery() {
        let (mut helper, model) = attach(fixture(false, false));
        assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
        for message in [
            MsiMessage {
                address: 1 << 32,
                ..MESSAGE
            },
            MsiMessage {
                address: MESSAGE.address | 1,
                ..MESSAGE
            },
            MsiMessage {
                data: 1 << 16,
                ..MESSAGE
            },
        ] {
            assert_eq!(
                unsafe { helper.program(message) },
                Err(MsiError::InvalidMessage)
            );
        }
        assert!(
            !model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::Write(..)))
        );
        drop(unsafe { helper.release() }.unwrap());
    }
    #[test]
    fn failed_reads_and_rejected_writes_preserve_owners_and_refuse_authorization() {
        for (offset, width) in [(COMMAND, 2), (0x52, 2), (0x54, 4), (0x58, 2)] {
            let (mut helper, model) = attach(fixture(false, false));
            model.lock().unwrap().fail_read = Some((offset, width));
            assert_eq!(
                unsafe { helper.program(MESSAGE) },
                Err(MsiError::FailedRead { offset })
            );
            assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
            model.lock().unwrap().fail_read = None;
            drop(unsafe { helper.release() }.unwrap());
        }
        for (offset, width) in [(COMMAND, 2), (0x54, 4), (0x58, 2)] {
            let (mut helper, model) = attach(fixture(false, false));
            model.lock().unwrap().block_write = Some((offset, width));
            assert_eq!(
                unsafe { helper.program(MESSAGE) },
                Err(MsiError::Readback { offset })
            );
            assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
            model.lock().unwrap().block_write = None;
            drop(unsafe { helper.release() }.unwrap());
        }
    }
    #[test]
    fn failed_enable_or_mask_does_not_release_the_actual_config_or_root() {
        let f = fixture(true, true);
        let cd = f.config_drops.clone();
        let rd = f.root_drops.clone();
        let weak = Arc::downgrade(&f.root);
        let (mut helper, model) = attach(f);
        unsafe { helper.program(MESSAGE) }.unwrap();
        model.lock().unwrap().block_write = Some((0x52, 2));
        assert_eq!(
            unsafe { helper.unmask() },
            Err(MsiError::Readback { offset: 0x52 })
        );
        model.lock().unwrap().block_write = None;
        model.lock().unwrap().fail_read = Some((COMMAND, 2));
        assert!(unsafe { helper.release() }.is_err());
        let count = quarantined_configurations();
        drop(helper);
        assert!(quarantined_configurations() >= count.saturating_add(1));
        assert_eq!(cd.load(Ordering::Relaxed), 0);
        assert_eq!(rd.load(Ordering::Relaxed), 0);
        assert!(weak.upgrade().is_some());
    }
    #[test]
    fn enable_write_without_read_ack_quarantines_even_if_hardware_enabled() {
        let f = fixture(false, false);
        let config_drops = f.config_drops.clone();
        let root_drops = f.root_drops.clone();
        let (mut helper, model) = attach(f);
        unsafe { helper.program(MESSAGE) }.unwrap();
        model.lock().unwrap().fail_enable_ack = true;
        assert_eq!(
            unsafe { helper.unmask() },
            Err(MsiError::FailedRead { offset: 0x52 })
        );
        assert_eq!(model.lock().unwrap().get(0x52, 2) & 1, 1);
        drop(helper);
        assert_eq!(config_drops.load(Ordering::Relaxed), 0);
        assert_eq!(root_drops.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn all_ones_admission_reads_do_not_mutate_or_consume_the_returned_owners() {
        for (offset, width) in [(0, 4), (STATUS, 2), (0x50, 2), (0x52, 2)] {
            let f = fixture(false, false);
            f.model.lock().unwrap().fail_read = Some((offset, width));
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("failed config read admitted"),
            };
            assert_eq!(error, MsiError::FailedRead { offset });
            assert!(
                !f.model
                    .lock()
                    .unwrap()
                    .events
                    .iter()
                    .any(|e| matches!(e, Event::Write(..)))
            );
            assert_eq!(f.config_drops.load(Ordering::Relaxed), 0);
            assert_eq!(f.root_drops.load(Ordering::Relaxed), 0);
            drop(owners);
            assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
            assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn each_real_capability_layout_has_a_checked_full_config_boundary() {
        for (wide, mask, offset, length) in [
            (false, false, 0xf4u16, 10usize),
            (true, false, 0xf0, 14),
            (false, true, 0xec, 20),
            (true, true, 0xe8, 24),
        ] {
            let f = fixture(wide, mask);
            {
                let mut m = f.model.lock().unwrap();
                m.bytes
                    .copy_within(0x50..0x50 + length, usize::from(offset));
                m.put(0x34, 1, u32::from(offset));
            }
            let (mut helper, _) = attach(f);
            unsafe { helper.program(MESSAGE) }.unwrap();
            unsafe { helper.unmask() }.unwrap();
            drop(unsafe { helper.release() }.unwrap());
            let f = fixture(wide, mask);
            {
                let mut m = f.model.lock().unwrap();
                let too_far = offset + 4;
                m.put(0x34, 1, u32::from(too_far));
                m.put(too_far, 2, u32::from(MSI));
                let flags = m.get(0x52, 2);
                m.put(too_far + 2, 2, flags);
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("truncated layout admitted"),
            };
            assert_eq!(error, MsiError::MalformedCapability);
            drop(owners);
        }
    }
    #[test]
    fn changed_identity_layout_or_message_cannot_reenable_a_stale_route() {
        for changed in [0, 0x52, 0x54] {
            let (mut helper, model) = attach(fixture(false, false));
            unsafe { helper.program(MESSAGE) }.unwrap();
            let old = {
                let mut m = model.lock().unwrap();
                let old = m.get(changed, if changed == 0x52 { 2 } else { 4 });
                m.put(
                    changed,
                    if changed == 0x52 { 2 } else { 4 },
                    old ^ if changed == 0x52 { u32::from(WIDE) } else { 4 },
                );
                old
            };
            let expected = match changed {
                0 => MsiError::IdentityChanged,
                0x52 => MsiError::CapabilityChanged,
                _ => MsiError::Readback { offset: 0x54 },
            };
            assert_eq!(unsafe { helper.unmask() }, Err(expected));
            model
                .lock()
                .unwrap()
                .put(changed, if changed == 0x52 { 2 } else { 4 }, old);
            drop(unsafe { helper.release() }.unwrap());
        }
    }
}
