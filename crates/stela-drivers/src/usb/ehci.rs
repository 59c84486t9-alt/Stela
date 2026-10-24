//! Polled native EHCI 1.0 high-speed control and bulk backend.
//!
//! This library owns its PCI, uncached BAR and requester-domain DMA resources.
//! It deliberately has no xHCI identities or native class-driver adapter. One
//! transfer runs at a time. Every inspection/cancellation stops the complete
//! asynchronous schedule, observes ASS=0 and drains actual posted DMA writes
//! before touching its reusable QH/qTD/bounce arena. Uncertain transitions
//! permanently quarantine the complete attachment, not just the failed TD.
//!
//! Full/low-speed traffic is handed to companions; split, periodic, ISO, hub,
//! suspend/resume and controller-specific quirks remain unsupported. These
//! boundaries make this an incomplete EHCI-family implementation.
mod descriptor;
mod native;
mod schedule;
#[cfg(test)]
mod tests;

use crate::bus::dma::{
    mapping::{Direction, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError},
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::{mem, ptr};
use native::Hardware;
pub use native::{Failure, NativeResources, attach};
use schedule::{Arena, Pending};

pub const CLASS: [u8; 3] = [0x0c, 0x03, 0x20];
pub const MAX_TRANSFER: usize = 65_536;
const TRANSITION_US: u64 = 100_000;
const RESET_US: u64 = 1_000_000;
const CMD: usize = 0;
const STS: usize = 4;
const INTR: usize = 8;
const SEGMENT: usize = 0x10;
const ASYNC: usize = 0x18;
const CONFIG: usize = 0x40;
const PORT: usize = 0x44;
const RUN: u32 = 1;
const RESET: u32 = 2;
const ASE: u32 = 1 << 5;
const PSE: u32 = 1 << 4;
const HALT: u32 = 1 << 12;
const ASS: u32 = 1 << 15;
const PSS: u32 = 1 << 14;
const FATAL: u32 = 1 << 4;
const CONNECT: u32 = 1;
const ENABLE: u32 = 1 << 2;
const OVERCURRENT: u32 = 1 << 4;
const PORT_RESET: u32 = 1 << 8;
const POWER: u32 = 1 << 12;
const OWNER: u32 = 1 << 13;
const PORT_CHANGES: u32 = (1 << 1) | (1 << 3) | (1 << 5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unsupported(&'static str),
    Invalid,
    Stale,
    Busy,
    Timeout,
    Removed,
    Device(u32),
    Quarantined,
    Dma(DmaError),
    Memory(MemoryError),
    Register,
    Exhausted,
}
impl From<DmaError> for Error {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

/// An unforgeable identity minted only after this owner's actual HS root reset.
/// Copies remain tombstones after disconnect, another reset or controller stop.
#[derive(Clone)]
pub struct DeviceId {
    owner: Rc<()>,
    generation: u64,
    port: u8,
}
/// A bulk endpoint from a configuration actually fetched and selected over USB.
#[derive(Clone)]
pub struct BulkPipe {
    device: DeviceId,
    configuration: u64,
    endpoint: u8,
}
impl BulkPipe {
    pub fn endpoint_address(&self) -> u8 {
        self.endpoint
    }
}
impl DeviceId {
    pub fn root_port(&self) -> u8 {
        self.port
    }
}
/// One specific transfer; old tickets cannot cancel or consume a newer transfer.
pub struct TransferId {
    device: DeviceId,
    serial: u64,
}
#[derive(Debug, Eq, PartialEq)]
pub struct Completion {
    pub actual: usize,
    pub data: Vec<u8>,
}

struct Device {
    generation: u64,
    address: u8,
    configuration: u64,
    endpoints: [Option<Endpoint>; 32],
}
#[derive(Clone, Copy)]
struct Endpoint {
    toggle: bool,
    ping: bool,
    halted: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Running,
    Failed,
    Stopped,
}

pub struct Controller {
    hardware: Option<Box<dyn Hardware>>,
    arena: Option<Arena>,
    owner: Rc<()>,
    state: State,
    operational: usize,
    ports: Vec<Option<Device>>,
    next_generation: u64,
    next_transfer: u64,
    default_port: Option<u8>,
    power_control: bool,
    companions: bool,
    pending: Option<Pending>,
}
impl Controller {
    fn hw(&mut self) -> &mut dyn Hardware {
        &mut **self.hardware.as_mut().expect("retained attachment")
    }
    fn read(&mut self, at: usize) -> Result<u32, Error> {
        let value = self.hw().read32(at)?;
        if value == u32::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn write(&mut self, at: usize, value: u32) -> Result<(), Error> {
        self.hw().write32(at, value)
    }
    fn op(&mut self, at: usize) -> Result<u32, Error> {
        self.read(self.operational + at)
    }
    fn put(&mut self, at: usize, value: u32) -> Result<(), Error> {
        self.write(self.operational + at, value)
    }
    fn ready(&self) -> Result<(), Error> {
        if self.state == State::Running {
            Ok(())
        } else {
            Err(Error::Quarantined)
        }
    }
    fn identity(&self, id: &DeviceId) -> Result<usize, Error> {
        if !Rc::ptr_eq(&self.owner, &id.owner) {
            return Err(Error::Stale);
        }
        let index = usize::from(id.port).checked_sub(1).ok_or(Error::Stale)?;
        if self
            .ports
            .get(index)
            .and_then(Option::as_ref)
            .is_none_or(|device| device.generation != id.generation)
        {
            return Err(Error::Stale);
        }
        self.ready()?;
        Ok(index)
    }
    fn port_at(&self, index: usize) -> usize {
        self.operational + PORT + 4 * index
    }
    fn live(&mut self, id: &DeviceId) -> Result<usize, Error> {
        let index = self.identity(id)?; // No hardware access before identity validation.
        let result = self.read(self.port_at(index));
        let value = self.guard(result)?;
        if value & (CONNECT | ENABLE | OWNER | OVERCURRENT | PORT_RESET | PORT_CHANGES)
            != CONNECT | ENABLE
        {
            self.ports[index] = None;
            if self.default_port == Some(id.port) {
                self.default_port = None;
            }
            if self.pending.is_some() {
                self.state = State::Failed;
            }
            return Err(Error::Stale);
        }
        let result = self.health();
        self.guard(result)?;
        Ok(index)
    }
    fn health(&mut self) -> Result<(), Error> {
        let status = self.op(STS)?;
        if status & (FATAL | HALT | PSS) != 0 {
            return Err(Error::Device(status));
        }
        Ok(())
    }
    fn wait(&mut self, at: usize, mask: u32, wanted: u32, timeout: u64) -> Result<(), Error> {
        let start = self.hw().now_us();
        loop {
            let value = self.read(at)?;
            if value & mask == wanted {
                return Ok(());
            }
            if self.hw().now_us().saturating_sub(start) >= timeout {
                return Err(Error::Timeout);
            }
            self.hw().pause();
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.state = State::Failed;
        Err(error)
    }
    fn guard<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
    fn schedule_off(&mut self) -> Result<(), Error> {
        self.health()?;
        let command = self.op(CMD)?;
        // Never reverse a pending schedule transition. Periodic is never ours.
        if command & PSE != 0 {
            return Err(Error::Unsupported("EHCI periodic schedule"));
        }
        self.wait(
            self.operational + STS,
            ASS,
            if command & ASE != 0 { ASS } else { 0 },
            TRANSITION_US,
        )?;
        self.put(CMD, command & !ASE)?;
        self.wait(self.operational + STS, ASS, 0, TRANSITION_US)?;
        self.health()?;
        // ASS0 is engine quiescence, not a remapper payload-write drain.
        self.hw().drain()?;
        let arena = self.arena.as_ref().ok_or(Error::Invalid)?;
        // SAFETY: actual ASS0 + actual requester path drain; no periodic engines.
        unsafe {
            arena.dma.sync_for_cpu(0..arena.bytes())?;
        }
        Ok(())
    }
    fn schedule_on(&mut self) -> Result<(), Error> {
        self.health()?;
        self.wait(self.operational + STS, ASS, 0, TRANSITION_US)?;
        let arena = self.arena.as_ref().ok_or(Error::Invalid)?;
        arena.dma.sync_for_device(0..arena.bytes())?;
        let command = self.op(CMD)?;
        self.put(CMD, command | ASE)?;
        self.wait(self.operational + STS, ASS, ASS, TRANSITION_US)?;
        self.health()
    }

    /// Reset a powered root with no active TD. Another default-address owner
    /// must first be addressed or explicitly disconnected. Reset retires all
    /// old handles before its first hardware effect, including failed resets.
    pub fn reset_port(&mut self, port: u8) -> Result<DeviceId, Error> {
        self.ready()?;
        let index = usize::from(port)
            .checked_sub(1)
            .filter(|index| *index < self.ports.len())
            .ok_or(Error::Invalid)?;
        if self.pending.is_some() || self.default_port.is_some_and(|owner| owner != port) {
            return Err(Error::Busy);
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.next_generation = generation;
        self.ports[index] = None;
        self.default_port = None;
        let result = self.reset_root(index);
        if let Err(error) = result {
            // A clean companion handoff / disconnected port is an explicit
            // unsupported device, not uncertainty in our schedule ownership.
            if !matches!(
                error,
                Error::Unsupported("EHCI companion-owned root" | "EHCI FS/LS companion traffic")
                    | Error::Stale
            ) {
                self.state = State::Failed;
            }
            return Err(error);
        }
        self.ports[index] = Some(Device {
            generation,
            address: 0,
            configuration: 0,
            endpoints: [None; 32],
        });
        self.default_port = Some(port);
        Ok(DeviceId {
            owner: self.owner.clone(),
            generation,
            port,
        })
    }
    fn reset_root(&mut self, index: usize) -> Result<(), Error> {
        self.schedule_off()?;
        let at = self.port_at(index);
        let mut value = self.read(at)?;
        if value & OWNER != 0 {
            return Err(Error::Unsupported("EHCI companion-owned root"));
        }
        if self.power_control && value & POWER == 0 {
            self.write(at, (value & !PORT_CHANGES) | POWER)?;
            self.hw().delay_us(20_000)?;
            value = self.read(at)?;
            if value & POWER == 0 {
                return Err(Error::Device(value));
            }
        }
        if value & CONNECT == 0 || value & OVERCURRENT != 0 {
            return Err(Error::Stale);
        }
        // Debounce actual connectivity, acknowledging only observed changes.
        self.write(at, (value & !PORT_CHANGES) | (value & PORT_CHANGES))?;
        self.hw().delay_us(100_000)?;
        value = self.read(at)?;
        if value & CONNECT == 0 || value & (OWNER | OVERCURRENT | PORT_CHANGES) != 0 {
            return Err(Error::Stale);
        }
        self.write(at, (value & !(PORT_CHANGES | ENABLE)) | PORT_RESET)?;
        self.hw().delay_us(50_000)?;
        value = self.read(at)?;
        self.write(at, value & !(PORT_CHANGES | PORT_RESET))?;
        self.wait(at, PORT_RESET, 0, TRANSITION_US)?;
        self.hw().delay_us(10_000)?;
        value = self.read(at)?;
        if value & CONNECT == 0
            || value & (OVERCURRENT | OWNER | PORT_RESET | (1 << 1) | (1 << 5)) != 0
        {
            return Err(Error::Stale);
        }
        // PE is only set by a successful high-speed reset/chirp; never set it.
        if value & ENABLE == 0 {
            if self.companions {
                self.write(at, (value & !PORT_CHANGES) | OWNER)?;
                self.wait(at, OWNER, OWNER, TRANSITION_US)?;
            }
            return Err(Error::Unsupported("EHCI FS/LS companion traffic"));
        }
        self.write(at, (value & !PORT_CHANGES) | (value & PORT_CHANGES))?;
        self.health()
    }

    /// Observe actual retained roots. Disconnect/change invalidates old IDs
    /// before any arena access. An active affected TD permanently quarantines
    /// the controller; an idle disconnect releases only its address0 owner.
    pub fn refresh_roots(&mut self) -> Result<Vec<u8>, Error> {
        self.ready()?;
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(self.ports.len())
            .map_err(|_| Error::Exhausted)?;
        for index in 0..self.ports.len() {
            if self.ports[index].is_none() {
                continue;
            }
            let result = self.read(self.port_at(index));
            let value = self.guard(result)?;
            if value & (CONNECT | ENABLE | OWNER | OVERCURRENT | PORT_RESET | PORT_CHANGES)
                != CONNECT | ENABLE
            {
                let port = (index + 1) as u8;
                self.ports[index] = None;
                if self.default_port == Some(port) {
                    self.default_port = None;
                }
                removed.push(port);
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.root_port() == port)
                {
                    return self.fail(Error::Stale);
                }
                // Leave PORTSC unchanged: replaying an unexpected reset/
                // resume/owner bit is not authorized by observing a change.
                // A later explicit root reset owns its W1C acknowledgments.
            }
        }
        let result = self.health();
        self.guard(result)?;
        Ok(removed)
    }

    /// Select a unique USB address through a real successful SET_ADDRESS TD.
    pub fn set_address(&mut self, id: &DeviceId, address: u8) -> Result<(), Error> {
        let index = self.identity(id)?;
        if address == 0
            || address > 127
            || self.ports[index].as_ref().expect("validated").address != 0
            || self
                .ports
                .iter()
                .flatten()
                .any(|device| device.address == address)
        {
            return Err(Error::Invalid);
        }
        self.control_internal(id, [0, 5, address, 0, 0, 0, 0, 0], &[], 0)?;
        let delay = self.hw().delay_us(2_000);
        self.guard(delay)?;
        self.ports[index].as_mut().expect("retained").address = address;
        self.default_port = None;
        Ok(())
    }

    /// Execute a bounded control request. Standard address/configuration and
    /// endpoint-halt mutations use their owning methods, preserving pipe state.
    pub fn control_in(&mut self, id: &DeviceId, setup: [u8; 8]) -> Result<Vec<u8>, Error> {
        self.identity(id)?;
        Self::public_control(setup)?;
        if setup[0] & 0x80 == 0 {
            return Err(Error::Invalid);
        }
        self.control_internal(
            id,
            setup,
            &[],
            usize::from(u16::from_le_bytes([setup[6], setup[7]])),
        )
    }
    pub fn control_out(&mut self, id: &DeviceId, setup: [u8; 8], data: &[u8]) -> Result<(), Error> {
        self.identity(id)?;
        Self::public_control(setup)?;
        if setup[0] & 0x80 != 0
            || usize::from(u16::from_le_bytes([setup[6], setup[7]])) != data.len()
        {
            return Err(Error::Invalid);
        }
        self.control_internal(id, setup, data, 0).map(|_| ())
    }
    fn public_control(setup: [u8; 8]) -> Result<(), Error> {
        if setup[0] & 0x60 == 0 && matches!(setup[1], 1 | 3 | 5 | 9 | 11) {
            return Err(Error::Unsupported("EHCI state-changing standard request"));
        }
        Ok(())
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        // No Drop can invent a hardware ACK or drain. Preserve PCI/UC roots,
        // domain, CPU aliases and pages together for any running/failed owner.
        if self.state != State::Stopped {
            if let Some(arena) = self.arena.take() {
                mem::forget(arena);
            }
            if let Some(hardware) = self.hardware.take() {
                mem::forget(hardware);
            }
        }
    }
}
