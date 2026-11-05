// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI configuration model and shared fixtures.
extern crate std;
mod fallible;
use super::*;
use crate::bus::pci::{ConfigError, ConfigFailure, regs};
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
    panic_read: Option<(u16, u8)>,
    panic_write: Option<(u16, u8)>,
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
    fn read(&self, offset: u16, width: u8) -> Result<u32, ConfigError> {
        let mut m = self.model.lock().unwrap();
        m.events.push(Event::Read(offset, width));
        if m.panic_read == Some((offset, width)) {
            drop(m);
            panic!("interrupted configuration observation");
        }
        let fault = m
            .fault_at_access
            .filter(|&(access, _)| access == m.events.len());
        if m.transport_dead || fault == Some((m.events.len(), false)) {
            m.transport_dead = true;
            return Err(ConfigError::before_effect(ConfigFailure::Mapping(
                crate::bus::mmio::owned::Error::Unavailable,
            )));
        }
        let value = if m.fail_read == Some((offset, width)) {
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
            return Err(ConfigError::before_effect(ConfigFailure::Mapping(
                crate::bus::mmio::owned::Error::Unavailable,
            )));
        }
        Ok(value)
    }
    fn write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), ConfigError> {
        assert!(
            !(offset == regs::COMMAND && width == 4),
            "dword Command RMW would replay adjacent Status W1C"
        );
        let mut m = self.model.lock().unwrap();
        m.events.push(Event::Write(offset, width, value));
        let fault = m
            .fault_at_access
            .filter(|&(access, _)| access == m.events.len());
        if m.transport_dead || fault == Some((m.events.len(), false)) {
            m.transport_dead = true;
            return Err(ConfigError::before_effect(ConfigFailure::Mapping(
                crate::bus::mmio::owned::Error::Unavailable,
            )));
        }
        if m.block_write != Some((offset, width)) {
            m.put(offset, width, value);
            if m.fail_enable_ack && offset == 0x52 && value & 1 != 0 {
                m.fail_read = Some((0x52, 2));
            }
        }
        if m.panic_write == Some((offset, width)) {
            drop(m);
            panic!("interrupted configuration publication");
        }
        if fault.is_some() {
            m.transport_dead = true;
            return Err(ConfigError::write_may_have_applied(
                offset,
                width,
                ConfigFailure::Mapping(crate::bus::mmio::owned::Error::Unavailable),
            ));
        }
        Ok(())
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.read(offset, 1).map(|value| value as u8)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.write(offset, 1, u32::from(value))
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.read(offset, 2).map(|value| value as u16)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.write(offset, 2, u32::from(value))
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.read(offset, 4)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.write(offset, 4, value)
    }
}
// SAFETY: each width-specific store copies only those bytes under the kept
// Arc/Mutex model; write16 never reads or replays the adjacent Status word.
// Every access is synchronous RAM with exclusive mutation under that mutex.
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
        panic_read: None,
        panic_write: None,
    };
    model.put(0, 4, 0x1234_8086);
    model.put(regs::COMMAND, 2, 0x107); // BM, IO, memory and unrelated SERR bit.
    model.put(regs::STATUS, 2, 0xa510); // includes live W1C bits and CapList.
    model.put(0x34, 1, 0x50);
    model.put(0x50, 2, u32::from(MSI));
    model.put(
        0x52,
        2,
        u32::from(
            (if wide { WIDE } else { 0 }) | (if mask { MASK_CAPABLE } else { 0 }) | 5 << 1 | 5 << 4,
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
    // SAFETY: fixture owns the exact RAM-backed Function and root guard; Arc/Mutex
    // keeps config backing live and serializes accesses. No device, posted IRQ,
    // callback, DMA or reset user exists, so the synthetic route is quiescent.
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
    assert_closed(helper, model, MsiError::TerminalRetirement);
}
fn assert_closed(helper: &mut MsiConfig<Config>, model: &Arc<Mutex<Model>>, expected: MsiError) {
    let before = model.lock().unwrap().events.len();
    assert_eq!(helper.mask(), Err(expected));
    assert_eq!(helper.disable(), Err(expected));
    assert_eq!(
        // SAFETY: this terminal RAM model keeps the original config/root guards.
        // No asynchronous source exists; programming must fail before register access.
        unsafe { helper.program(MESSAGE) },
        Err(expected)
    );
    assert_eq!(
        // SAFETY: The terminal model keeps the original config/root owners; this
        // rejected unmask must not reach any register or callback.
        unsafe { helper.unmask() },
        Err(expected)
    );
    assert_eq!(helper.begin_device_retirement().err(), Some(expected));
    assert_eq!(
        // SAFETY: the closed model has no asynchronous users and must retain owners.
        unsafe { helper.release() }.err(),
        Some(expected),
    );
    assert_eq!(model.lock().unwrap().events.len(), before);
}

mod admission;
mod aliases;
mod extents;
mod failures;
mod programming;
mod retirement;
