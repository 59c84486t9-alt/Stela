// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig.
// Copyright (c) 2026 Stela contributors
//! Single-message PCI MSI configuration with retained real config ownership.
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

/// Owns the original Function and actual retained PCI/config/root/reset epoch.
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
    /// write, IRQ or worker completion. The registry retains its route/callbacks
    /// while the terminal owner performs the real source stop.
    ///
    /// Authorization is revoked before even the first configuration access.
    /// Failure retains the actual owner here with no program/unmask/retry path.
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
            // All-ones is a valid mask bitmap. Presence/control reads qualify
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
    /// This typed message belongs to the actual registry's qualified route;
    /// every callback/resource remains retained. Reprogramming requires real
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
    /// The actual registry retains/publishes the callback and qualified route;
    /// the requester and all IRQ/DMA/work/reset owners remain retained. BM and
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
        fault_at_access: Option<(usize, bool)>,
        transport_dead: bool,
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
            let fault = m
                .fault_at_access
                .filter(|&(access, _)| access == m.events.len());
            let failed = m.transport_dead
                || m.fail_read == Some((offset, width))
                || fault == Some((m.events.len(), false));
            let value = if failed {
                match width {
                    1 => 0xff,
                    2 => 0xffff,
                    _ => u32::MAX,
                }
            } else {
                m.get(offset, width)
            };
            if fault.is_some() {
                m.transport_dead = true;
            }
            value
        }
        fn write(&mut self, offset: u16, width: u8, value: u32) {
            assert!(
                !(offset == COMMAND && width == 4),
                "dword Command RMW would replay adjacent Status W1C"
            );
            let mut m = self.model.lock().unwrap();
            m.events.push(Event::Write(offset, width, value));
            let fault = m
                .fault_at_access
                .filter(|&(access, _)| access == m.events.len());
            if !m.transport_dead
                && m.block_write != Some((offset, width))
                && fault != Some((m.events.len(), false))
            {
                m.put(offset, width, value);
                if m.fail_enable_ack && offset == 0x52 && value & 1 != 0 {
                    m.fail_read = Some((0x52, 2));
                }
            }
            if fault.is_some() {
                m.transport_dead = true;
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
            self.read(offset, 1) as u8
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
            fault_at_access: None,
            transport_dead: false,
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

    fn assert_terminal(helper: &mut MsiConfig<Config>, model: &Arc<Mutex<Model>>) {
        let before = model.lock().unwrap().events.len();
        assert_eq!(helper.mask(), Err(MsiError::TerminalRetirement));
        assert_eq!(helper.disable(), Err(MsiError::TerminalRetirement));
        // SAFETY: isolated qualified model route; terminal calls must fail
        // before touching hardware regardless of the old authorization.
        assert_eq!(
            unsafe { helper.program(MESSAGE) },
            Err(MsiError::TerminalRetirement)
        );
        assert_eq!(
            unsafe { helper.unmask() },
            Err(MsiError::TerminalRetirement)
        );
        assert!(matches!(
            helper.begin_device_retirement(),
            Err(MsiError::TerminalRetirement)
        ));
        assert!(matches!(
            unsafe { helper.release() },
            Err(MsiError::TerminalRetirement)
        ));
        assert_eq!(model.lock().unwrap().events.len(), before);
    }
    #[test]
    fn terminal_stop_preserves_original_owners_and_releases_without_powered_config_access() {
        for wide in [false, true] {
            for mask in [false, true] {
                let f = fixture(wide, mask);
                let configs = f.config_drops.clone();
                let roots = f.root_drops.clone();
                let (mut helper, model) = attach(f);
                // SAFETY: isolated qualified message/source/callback model.
                unsafe { helper.program(MESSAGE) }.unwrap();
                unsafe { helper.unmask() }.unwrap();
                // Ordinary admission masking remains reversible.
                helper.mask().unwrap();
                unsafe { helper.unmask() }.unwrap();
                let mut terminal = helper.begin_device_retirement().unwrap();
                assert_terminal(&mut helper, &model);
                assert_eq!(terminal.address().unwrap().device, 2);
                {
                    let m = model.lock().unwrap();
                    assert_eq!(m.get(0x52, 2) & u32::from(ENABLE), 0);
                    assert_ne!(m.get(COMMAND, 2) & u32::from(INTX_DISABLE), 0);
                    assert_eq!(m.get(STATUS, 2), 0xa510);
                }
                // SAFETY: synchronous actual config model, no device/IRQ users;
                // this is the single terminal stop, with no BM/MSI re-enable.
                let original = unsafe {
                    terminal.with_device_stop(|config| {
                        let command = config.read16(COMMAND);
                        config.write16(COMMAND, command & !4);
                        command
                    })
                }
                .unwrap();
                assert_ne!(original & 4, 0);
                assert_eq!(model.lock().unwrap().get(COMMAND, 2) & 4, 0);
                // The original config transport can now be genuinely inaccessible.
                model.lock().unwrap().transport_dead = true;
                let before = model.lock().unwrap().events.len();
                // SAFETY: isolated fixture has no DMA/posted/IRQ/deferred users;
                // their actual empty completion is independent of BM-clear.
                let owners = unsafe { terminal.release_after_drain() }.unwrap();
                assert_eq!(model.lock().unwrap().events.len(), before);
                drop(owners);
                assert_eq!(configs.load(Ordering::Relaxed), 1);
                assert_eq!(roots.load(Ordering::Relaxed), 1);
                assert_eq!(terminal.address(), Err(MsiError::Released));
                assert!(matches!(
                    unsafe { terminal.release_after_drain() },
                    Err(MsiError::Released)
                ));
            }
        }
    }
    #[test]
    fn every_before_after_disable_access_fault_is_terminal_and_retains_actual_epoch() {
        for wide in [false, true] {
            for mask in [false, true] {
                let (mut baseline, model) = attach(fixture(wide, mask));
                unsafe { baseline.program(MESSAGE) }.unwrap();
                unsafe { baseline.unmask() }.unwrap();
                model.lock().unwrap().events.clear();
                let terminal = baseline.begin_device_retirement().unwrap();
                let count = model.lock().unwrap().events.len();
                drop(terminal); // live terminal abandonment retains both real guards.
                for access in 1..=count {
                    for after in [false, true] {
                        let f = fixture(wide, mask);
                        let configs = f.config_drops.clone();
                        let roots = f.root_drops.clone();
                        let (mut helper, model) = attach(f);
                        unsafe { helper.program(MESSAGE) }.unwrap();
                        unsafe { helper.unmask() }.unwrap();
                        {
                            let mut m = model.lock().unwrap();
                            m.events.clear();
                            m.fault_at_access = Some((access, after));
                        }
                        let result = helper.begin_device_retirement();
                        assert!(model.lock().unwrap().transport_dead);
                        assert_terminal(&mut helper, &model);
                        // A successful final ACK followed by loss may transfer
                        // the original owner, but cannot create a stop proof.
                        drop(result);
                        drop(helper);
                        assert_eq!(
                            configs.load(Ordering::Relaxed),
                            0,
                            "config freed access={access},after={after}"
                        );
                        assert_eq!(
                            roots.load(Ordering::Relaxed),
                            0,
                            "root freed access={access},after={after}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn unwinding_after_a_real_stop_effect_cannot_replay_or_release_the_original_owner() {
        let f = fixture(true, true);
        let configs = f.config_drops.clone();
        let roots = f.root_drops.clone();
        let (mut helper, model) = attach(f);
        let mut terminal = helper.begin_device_retirement().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: isolated actual config model, one terminal stop with a
            // deliberate post-effect unwind; no configuration escape/re-enable.
            unsafe {
                terminal.with_device_stop::<()>(|config| {
                    config.write16(COMMAND, INTX_DISABLE);
                    panic!("modeled caller unwind after actual stop effect");
                })
            }
        }));
        assert!(result.is_err());
        assert_eq!(
            model.lock().unwrap().get(COMMAND, 2),
            u32::from(INTX_DISABLE)
        );
        let before = model.lock().unwrap().events.len();
        assert_eq!(
            unsafe { terminal.with_device_stop::<()>(|_| panic!("replay after unwind")) },
            Err(MsiError::StopAlreadyAttempted)
        );
        assert_eq!(model.lock().unwrap().events.len(), before);
        drop(terminal);
        drop(helper);
        assert_eq!(configs.load(Ordering::Relaxed), 0);
        assert_eq!(roots.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concrete_owned_config_epoch_survives_terminal_transfer_and_uncertain_abandonment() {
        use crate::bus::pci::owned::tests::fixture as owned_fixture;
        for abandon in [false, true] {
            let address = Address {
                segment: 7,
                bus: 3,
                device: 4,
                function: 1,
            };
            let (mut config, counters) = owned_fixture(address);
            config.write32(0, 0x1234_8086);
            config.write16(COMMAND, 0x107);
            config.write16(STATUS, CAP_LIST);
            config.write8(0x34, 0x50);
            config.write16(0x50, u16::from(MSI));
            config.write16(0x52, WIDE | MASK_CAPABLE);
            let function = Function::new(address, config).unwrap();
            let root_drops = Arc::new(AtomicU64::new(0));
            let root: RetainedOwner = Arc::new(Root(root_drops.clone()));
            // SAFETY: original isolated registry-owned RAM config epoch, no
            // device, IRQ delivery, worker or production qualification exists.
            let mut helper = match unsafe { MsiConfig::new(function, root) } {
                Ok(helper) => helper,
                Err((error, _)) => panic!("valid actual owned transport: {error:?}"),
            };
            let mut terminal = helper.begin_device_retirement().unwrap();
            assert_eq!(terminal.address(), Ok(address));
            // SAFETY: single synchronous stop of this isolated actual owner.
            let stopped = unsafe {
                terminal.with_device_stop(|config| {
                    let command = config.read16(COMMAND);
                    config.write16(COMMAND, command & !4);
                    config.read16(COMMAND) & 4 == 0
                })
            }
            .unwrap();
            assert!(stopped);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
            if abandon {
                drop(terminal);
                drop(helper);
                assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
                assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
                assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
                assert_eq!(root_drops.load(Ordering::Relaxed), 0);
            } else {
                // SAFETY: the isolated real resource has no async users; empty
                // device/IRQ completion is known independently of config bits.
                let (function, root) = unsafe { terminal.release_after_drain() }.unwrap();
                let mut mapping = function.into_config().into_mapping();
                // SAFETY: exact original mapping, all synchronous users ended.
                unsafe { mapping.retire() }.unwrap();
                drop(root);
                assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
                assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
                assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
                assert_eq!(root_drops.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[test]
    fn an_uncertain_terminal_device_stop_cannot_retry_or_release_actual_resources_on_drop() {
        let f = fixture(true, true);
        let configs = f.config_drops.clone();
        let roots = f.root_drops.clone();
        let (mut helper, model) = attach(f);
        let mut terminal = helper.begin_device_retirement().unwrap();
        // SAFETY: one actual isolated model stop; its precise failure remains
        // caller-visible, and supplies no quiescence or release authorization.
        let original: Result<(), u32> = unsafe {
            terminal.with_device_stop(|config| {
                config.write16(COMMAND, INTX_DISABLE);
                Err(0x4377_00ff)
            })
        }
        .unwrap();
        assert_eq!(original, Err(0x4377_00ff));
        let before = model.lock().unwrap().events.len();
        assert_eq!(
            unsafe { terminal.with_device_stop(|_| panic!("reset replay")) },
            Err::<(), _>(MsiError::StopAlreadyAttempted)
        );
        assert_eq!(model.lock().unwrap().events.len(), before);
        drop(terminal);
        drop(helper);
        assert_eq!(configs.load(Ordering::Relaxed), 0);
        assert_eq!(roots.load(Ordering::Relaxed), 0);
    }

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
        // Root-port and slot PCIe layouts are sized in full: the MSI header
        // at 0x50 lies inside their bodies.
        for (id, flags, expected) in [
            (7, 0x3000, MsiError::Unsupported),
            (0x10, 0, MsiError::Unsupported),
            (0x10, 3, MsiError::Unsupported),
            (0x10, 0x42, MsiError::MalformedCapability),
            (0x10, 0x102, MsiError::MalformedCapability),
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
            assert_eq!(error, expected);
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
