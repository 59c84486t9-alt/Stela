// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
// AMD MP2 I2C protocol adapted from Linux; Authors: Shyam Sundar S K,
// Elie Morisse, Nehal Bakulchandra Shah. See ../THIRD_PARTY.md.
//! Serialized AMD 1022:15e6 MP2 firmware mailbox and AMDI0011 bus engines.
//!
//! The two buses share one payload mailbox and are owned by one Controller.
//! Requests are individual firmware messages. Combined repeated-START semantics
//! are not established by the donor and are deliberately not fabricated here.
use super::{Address, Clock, Timer};
use crate::bus::dma::DmaBuffer;
use core::sync::atomic::{Ordering, fence};

const COMMAND: [usize; 2] = [0x10500, 0x10504];
const PAYLOAD: usize = 0x10508;
const EVENT: [usize; 2] = [0x10684, 0x10688];
const INTERRUPT: usize = 0x10690;
const INLINE: usize = 32;
pub const MAX_LENGTH: usize = 4095;
pub const VENDOR: u16 = 0x1022;
pub const DEVICE: u16 = 0x15e6;
pub const ACPI_ID: &str = "AMDI0011";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;
/// Ordered access to the actual MP2 BAR2 registers and byte payload window.
/// # Safety
/// The provider retains the actual exclusively owned PCI function, powered BAR2
/// UC mapping and firmware/reset epoch. No other CPU, firmware/AML driver or IRQ
/// handler accesses either bus or mailbox. It grants ordered volatile accesses;
/// errors may follow effects. It must remain valid when deliberately leaked.
pub unsafe trait Registers {
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
    fn read_payload(&mut self, bytes: &mut [u8]) -> Result<(), IoError>;
    fn write_payload(&mut self, bytes: &[u8]) -> Result<(), IoError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Speed {
    Khz100 = 0,
    Khz400 = 1,
    Mhz1 = 2,
    Mhz1_4 = 3,
    Mhz3_4 = 4,
}
impl Speed {
    /// Largest source-defined speed not exceeding the actual peripheral/board
    /// limit. An absent/too-low limit is refused, rather than guessed as 400kHz.
    pub fn from_limit(hz: u32) -> Result<Self, ErrorKind> {
        match hz {
            3_400_000.. => Ok(Self::Mhz3_4),
            1_400_000.. => Ok(Self::Mhz1_4),
            1_000_000.. => Ok(Self::Mhz1),
            400_000.. => Ok(Self::Khz400),
            100_000.. => Ok(Self::Khz100),
            _ => Err(ErrorKind::Configuration),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusId(u8);
impl BusId {
    /// The observed AMDI0011 `_UID`, with a separately established binding to
    /// this PCI function. Two MP2 devices cannot be associated by guesswork.
    pub fn from_uid(uid: u64) -> Result<Self, ErrorKind> {
        if uid < 2 {
            Ok(Self(uid as u8))
        } else {
            Err(ErrorKind::Configuration)
        }
    }
    pub fn get(self) -> u8 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Command {
    Read = 0,
    Write = 1,
    Enable = 2,
    Disable = 3,
}
impl Command {
    fn status(self) -> u32 {
        (self as u32) * 2
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    InvalidAddress,
    Length(usize),
    NotEnabled,
    Io,
    /// An unsolicited or stale response was present before publication.
    Pending,
    Timeout,
    /// Raw response is preserved even when the firmware reports failure.
    Response,
    NeedsReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub bus: u8,
    pub command: Option<u32>,
    pub event: Option<u32>,
    /// A mailbox or command write was attempted; it must not be replayed.
    pub published: bool,
}

/// Exclusive owner for both adapters, the shared mailbox and one retained DMA
/// bounce allocation. A timed-out command has no reset primitive in this
/// protocol: the whole owner is quarantined, including the other bus.
pub struct Controller<R: Registers + 'static, T: Timer + 'static = Clock> {
    owners: Option<(R, T, DmaBuffer)>,
    speeds: [Option<Speed>; 2],
    enabled: [bool; 2],
    timeout_us: u64,
    failed: Option<Error>,
    observed: Option<u32>,
    command: Option<u32>,
    published: bool,
    started: u64,
}
impl<R: Registers + 'static, T: Timer + 'static> Controller<R, T> {
    /// # Safety
    /// Registers retain the actual exclusive 1022:15e6 BAR2 owner. Both firmware
    /// buses are stopped and no old DMA/request/IRQ callback is outstanding.
    /// The platform masks actual PCI interrupt delivery for the complete polled
    /// lifetime; clearing the source event/INTEN registers is not a PCI mask.
    /// The supplied private bounce allocation is coherent, reachable by this
    /// actual requester, not shared, and remains pinned for the rest of boot.
    /// Speed inputs are observed board/peripheral limits; None means no adapter
    /// is granted. The clock is calibrated, monotonic and advancing.
    #[allow(clippy::type_complexity)]
    pub unsafe fn claim(
        registers: R,
        timer: T,
        buffer: DmaBuffer,
        speeds: [Option<Speed>; 2],
        timeout_us: u64,
    ) -> Result<Self, (ErrorKind, (R, T, DmaBuffer))> {
        if buffer.len() < MAX_LENGTH || timeout_us == 0 || speeds == [None, None] {
            return Err((ErrorKind::Configuration, (registers, timer, buffer)));
        }
        Ok(Self {
            owners: Some((registers, timer, buffer)),
            speeds,
            enabled: [false; 2],
            timeout_us,
            failed: None,
            observed: None,
            command: None,
            published: false,
            started: 0,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.failed
    }
    pub fn is_enabled(&self, bus: BusId) -> bool {
        self.enabled[usize::from(bus.0)]
    }
    fn error(&self, bus: BusId, kind: ErrorKind) -> Error {
        Error {
            kind,
            bus: bus.0,
            command: self.command,
            event: self.observed,
            published: self.published,
        }
    }
    fn io(&mut self, bus: BusId, result: Result<(), IoError>) -> Result<(), Error> {
        result.map_err(|_| self.error(bus, ErrorKind::Io))
    }
    fn write32(&mut self, bus: BusId, offset: usize, value: u32) -> Result<(), Error> {
        self.published = true;
        let result = self.owners.as_mut().unwrap().0.write32(offset, value);
        self.io(bus, result)?;
        self.deadline(bus)
    }
    fn read32(&mut self, bus: BusId, offset: usize) -> Result<u32, Error> {
        let value = self
            .owners
            .as_mut()
            .unwrap()
            .0
            .read32(offset)
            .map_err(|_| self.error(bus, ErrorKind::Io))?;
        if EVENT.contains(&offset) {
            self.observed = Some(value);
        }
        self.deadline(bus)?;
        Ok(value)
    }
    fn deadline(&self, bus: BusId) -> Result<(), Error> {
        if self
            .owners
            .as_ref()
            .unwrap()
            .1
            .now_us()
            .wrapping_sub(self.started)
            >= self.timeout_us
        {
            Err(self.error(bus, ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn prepare(&mut self, bus: BusId) -> Result<Speed, Error> {
        if self.failed.is_some() {
            return Err(self.error(bus, ErrorKind::NeedsReset));
        }
        self.command = None;
        self.observed = None;
        self.published = false;
        self.started = self.owners.as_ref().unwrap().1.now_us();
        self.speeds[usize::from(bus.0)].ok_or_else(|| self.error(bus, ErrorKind::Configuration))
    }
    fn preflight(&mut self, bus: BusId) -> Result<(), Error> {
        // A response cannot be silently consumed or mistaken for our new ACK.
        for offset in EVENT {
            let event = self.read32(bus, offset)?;
            if event != 0 {
                self.observed = Some(event);
                return Err(self.error(bus, ErrorKind::Pending));
            }
        }
        Ok(())
    }
    fn execute(
        &mut self,
        bus: BusId,
        cmd: Command,
        speed: Speed,
        address: u8,
        length: usize,
    ) -> Result<(), Error> {
        let inline = matches!(cmd, Command::Read | Command::Write) && length <= INLINE;
        let command = cmd as u32
            | u32::from(bus.0) << 4
            | u32::from(address) << 8
            | (length as u32) << 16
            | (speed as u32) << 28
            | u32::from(inline) << 31;
        self.command = Some(command);
        if length > INLINE {
            let physical = self.owners.as_ref().unwrap().2.physical();
            // Linux's writeq is explicitly low then high on this platform.
            self.write32(bus, PAYLOAD, physical as u32)?;
            self.write32(bus, PAYLOAD + 4, (physical >> 32) as u32)?;
        }
        fence(Ordering::SeqCst);
        self.deadline(bus)?;
        self.write32(bus, COMMAND[usize::from(bus.0)], command)?;
        loop {
            let event = self.read32(bus, EVENT[usize::from(bus.0)])?;
            if event != 0 {
                self.observed = Some(event);
            }
            self.deadline(bus)?;
            if event != 0 {
                // Match the actual completion before touching caller output.
                let response = event & 3;
                let status = (event >> 2) & 31;
                let event_bus = (event >> 8) & 15;
                let data_ok = !matches!(cmd, Command::Read | Command::Write)
                    || ((event >> 12) & 4095 == length as u32
                        && event >> 24 == u32::from(address)
                        && ((event >> 7) & 1 != 0) == inline);
                if response != 1
                    || status != cmd.status()
                    || event_bus != u32::from(bus.0)
                    || !data_ok
                {
                    return Err(self.error(bus, ErrorKind::Response));
                }
                self.write32(bus, EVENT[usize::from(bus.0)], 0)?;
                self.write32(bus, INTERRUPT, 0)?;
                fence(Ordering::SeqCst);
                self.deadline(bus)?;
                return Ok(());
            }
            self.owners.as_ref().unwrap().1.relax();
        }
    }
    fn finish(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(error) = result {
            // No donor timeout-unmap/retry: firmware can still own DMA/mailbox.
            self.failed = Some(error);
            self.enabled = [false; 2];
        }
        result
    }
    pub fn enable(&mut self, bus: BusId) -> Result<(), Error> {
        let speed = self.prepare(bus)?;
        if self.is_enabled(bus) {
            return Ok(());
        }
        let result = self
            .preflight(bus)
            .and_then(|()| self.execute(bus, Command::Enable, speed, 0, 0));
        self.finish(result)?;
        self.enabled[usize::from(bus.0)] = true;
        Ok(())
    }
    pub fn disable(&mut self, bus: BusId) -> Result<(), Error> {
        let speed = self.prepare(bus)?;
        if !self.is_enabled(bus) {
            return Ok(());
        }
        let result = self
            .preflight(bus)
            .and_then(|()| self.execute(bus, Command::Disable, speed, 0, 0));
        self.finish(result)?;
        self.enabled[usize::from(bus.0)] = false;
        Ok(())
    }
    fn data_preflight(
        &mut self,
        bus: BusId,
        address: Address,
        length: usize,
    ) -> Result<(Speed, u8), Error> {
        let speed = self.prepare(bus)?;
        let Address::SevenBit(address @ 0x08..=0x77) = address else {
            return Err(self.error(bus, ErrorKind::InvalidAddress));
        };
        if !(1..=MAX_LENGTH).contains(&length) {
            return Err(self.error(bus, ErrorKind::Length(length)));
        }
        if !self.is_enabled(bus) {
            return Err(self.error(bus, ErrorKind::NotEnabled));
        }
        Ok((speed, address))
    }
    /// One complete firmware write. No combined repeated START is claimed.
    pub fn write(&mut self, bus: BusId, address: Address, bytes: &[u8]) -> Result<(), Error> {
        let (speed, address) = self.data_preflight(bus, address, bytes.len())?;
        let result = (|| {
            self.preflight(bus)?;
            if bytes.len() <= INLINE {
                self.published = true;
                let result = self.owners.as_mut().unwrap().0.write_payload(bytes);
                self.io(bus, result)?;
                self.deadline(bus)?;
            } else {
                self.owners.as_mut().unwrap().2.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
            }
            self.execute(bus, Command::Write, speed, address, bytes.len())
        })();
        self.finish(result)
    }
    /// Read output is committed only after a matching actual event and all
    /// payload accesses succeed. Partial mailbox reads stay private on errors.
    pub fn read(&mut self, bus: BusId, address: Address, bytes: &mut [u8]) -> Result<(), Error> {
        let (speed, address) = self.data_preflight(bus, address, bytes.len())?;
        let result = (|| {
            self.preflight(bus)?;
            self.execute(bus, Command::Read, speed, address, bytes.len())?;
            if bytes.len() <= INLINE {
                let mut scratch = [0; INLINE];
                let result = self
                    .owners
                    .as_mut()
                    .unwrap()
                    .0
                    .read_payload(&mut scratch[..bytes.len()]);
                self.io(bus, result)?;
                self.deadline(bus)?;
                bytes.copy_from_slice(&scratch[..bytes.len()]);
            } else {
                bytes.copy_from_slice(&self.owners.as_ref().unwrap().2.bytes()[..bytes.len()]);
            }
            Ok(())
        })();
        self.finish(result)
    }
    /// Release only after both real disable acknowledgments and no uncertain
    /// request. The retained DMA allocation itself remains boot-lifetime pinned.
    pub fn release(mut self) -> Result<(R, T, DmaBuffer), Self> {
        if self.failed.is_some() || self.enabled != [false; 2] {
            return Err(self);
        }
        Ok(self.owners.take().unwrap())
    }
}
impl<R: Registers + 'static, T: Timer + 'static> Drop for Controller<R, T> {
    fn drop(&mut self) {
        if (self.failed.is_some() || self.enabled != [false; 2])
            && let Some(owners) = self.owners.take()
        {
            core::mem::forget(owners);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::{DmaAllocator, RegionAllocator};
    use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
    use core::cell::{Cell, RefCell};

    #[derive(Clone)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get().wrapping_add(1));
        }
    }
    #[derive(Clone, Debug)]
    enum Access {
        Read(usize),
        Write(usize, u32),
        PayloadRead(usize),
        PayloadWrite(Vec<u8>),
    }
    struct Device {
        time: Time,
        events: [u32; 2],
        enabled: [bool; 2],
        payload: [u8; 32],
        address: u64,
        log: Vec<Access>,
        delay: usize,
        remaining: usize,
        pending: Option<(usize, u32)>,
        corrupt: u32,
        hang: bool,
        fail: Option<(usize, bool)>,
        count: usize,
        late: Option<usize>,
        drops: Rc<Cell<usize>>,
    }
    impl Device {
        fn before(&mut self, access: Access) -> Result<(), IoError> {
            self.log.push(access);
            self.count += 1;
            if self.late == Some(self.count) {
                self.time.0.set(self.time.0.get().wrapping_add(100));
            }
            if self.fail == Some((self.count, false)) {
                return Err(IoError);
            }
            Ok(())
        }
        fn after(&self) -> Result<(), IoError> {
            if self.fail == Some((self.count, true)) {
                Err(IoError)
            } else {
                Ok(())
            }
        }
        fn complete(&mut self) {
            let Some((bus, word)) = self.pending.take() else {
                return;
            };
            let op = word & 15;
            let length = ((word >> 16) & 4095) as usize;
            let address = (word >> 8) & 255;
            let inline = word >> 31 != 0;
            if op == 2 {
                self.enabled[bus] = true;
            } else if op == 3 {
                self.enabled[bus] = false;
            } else {
                assert!(self.enabled[bus], "native sent data before enable");
                assert_eq!(inline, length <= 32);
                let data = if inline {
                    &mut self.payload[..length]
                } else {
                    // SAFETY: fixture owns a retained real region allocation and the
                    // actual firmware command/address selects its bounded payload.
                    unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, length) }
                };
                if op == 0 {
                    for (i, byte) in data.iter_mut().enumerate() {
                        *byte = (i as u8).wrapping_mul(31).wrapping_add(address as u8);
                    }
                } else {
                    for (i, byte) in data.iter().enumerate() {
                        assert_eq!(*byte, (i as u8).wrapping_mul(17).wrapping_add(3));
                    }
                }
            }
            self.events[bus] = (1
                | (op * 2) << 2
                | (inline as u32) << 7
                | (bus as u32) << 8
                | (length as u32) << 12
                | address << 24)
                ^ self.corrupt;
        }
    }
    impl Drop for Device {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    #[derive(Clone)]
    struct Model(Rc<RefCell<Device>>);
    // SAFETY: one controller serializes this single actual device model. Clones are
    // fixture inspection handles, never another mailbox driver.
    unsafe impl Registers for Model {
        fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
            let mut d = self.0.borrow_mut();
            d.before(Access::Read(offset))?;
            if let Some((bus, _)) = d.pending
                && offset == EVENT[bus]
                && !d.hang
            {
                if d.remaining == 0 {
                    d.complete();
                } else {
                    d.remaining -= 1;
                }
            }
            let value = if let Some(bus) = EVENT.iter().position(|x| *x == offset) {
                d.events[bus]
            } else {
                panic!("unexpected read {offset:x}");
            };
            d.after()?;
            Ok(value)
        }
        fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
            let mut d = self.0.borrow_mut();
            d.before(Access::Write(offset, value))?;
            if let Some(bus) = COMMAND.iter().position(|x| *x == offset) {
                assert!(d.pending.is_none());
                assert_eq!(d.events, [0; 2]);
                assert_eq!((value >> 4) & 15, bus as u32);
                d.pending = Some((bus, value));
                d.remaining = d.delay;
            } else if let Some(bus) = EVENT.iter().position(|x| *x == offset) {
                assert_eq!(value, 0);
                d.events[bus] = 0;
            } else if offset == INTERRUPT {
                assert_eq!(value, 0);
            } else if offset == PAYLOAD {
                d.address = d.address & (!0u64 << 32) | u64::from(value);
            } else if offset == PAYLOAD + 4 {
                d.address = d.address & u64::from(u32::MAX) | (u64::from(value) << 32);
            } else {
                panic!("unexpected write {offset:x}");
            }
            d.after()
        }
        fn read_payload(&mut self, bytes: &mut [u8]) -> Result<(), IoError> {
            let mut d = self.0.borrow_mut();
            d.before(Access::PayloadRead(bytes.len()))?;
            bytes.copy_from_slice(&d.payload[..bytes.len()]);
            d.after()
        }
        fn write_payload(&mut self, bytes: &[u8]) -> Result<(), IoError> {
            let mut d = self.0.borrow_mut();
            d.before(Access::PayloadWrite(bytes.to_vec()))?;
            d.payload[..bytes.len()].copy_from_slice(bytes);
            d.after()
        }
    }
    type Host = Controller<Model, Time>;
    fn fixture() -> (Host, Model, Rc<Cell<usize>>) {
        let time = Time(Rc::new(Cell::new(u64::MAX - 20)));
        let drops = Rc::new(Cell::new(0));
        let model = Model(Rc::new(RefCell::new(Device {
            time: time.clone(),
            events: [0; 2],
            enabled: [false; 2],
            payload: [0; 32],
            address: 0,
            log: Vec::new(),
            delay: 0,
            remaining: 0,
            pending: None,
            corrupt: 0,
            hang: false,
            fail: None,
            count: 0,
            late: None,
            drops: drops.clone(),
        })));
        // The existing RegionAllocator grants boot-lifetime identity DMA; the
        // fixture deliberately retains its actual heap allocation for that epoch.
        let raw = Box::leak(vec![0u8; 8192].into_boxed_slice());
        let start = raw.as_mut_ptr() as u64;
        // SAFETY: exclusively retained, mapped native RAM, no other allocator.
        let mut allocator = unsafe { RegionAllocator::new(start..start + 8192) };
        let buffer = allocator.allocate(MAX_LENGTH, 1).unwrap();
        // SAFETY: fixture has an exclusive initially stopped native model and
        // coherent retained payload; bus identity/speeds are explicit fixture facts.
        let host = unsafe {
            Controller::claim(
                model.clone(),
                time,
                buffer,
                [Some(Speed::Khz400), Some(Speed::Mhz1)],
                100,
            )
        }
        .ok()
        .unwrap();
        (host, model, drops)
    }
    fn bus(id: u64) -> BusId {
        BusId::from_uid(id).unwrap()
    }
    fn output(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
            .collect()
    }
    fn assert_read(bytes: &[u8], address: u8) {
        for (i, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, (i as u8).wrapping_mul(31).wrapping_add(address));
        }
    }

    #[test]
    fn two_actual_buses_all_lengths_inline_dma_and_power_lifecycle() {
        let (mut h, m, drops) = fixture();
        for id in 0..2 {
            h.enable(bus(id)).unwrap();
            for delay in [0, 1, 3] {
                m.0.borrow_mut().delay = delay;
                for length in [1, 2, 3, 7, 31, 32, 33, 39, 255, 4095] {
                    h.write(bus(id), Address::SevenBit(0x15), &output(length))
                        .unwrap();
                    let mut bytes = vec![0xa5; length];
                    h.read(bus(id), Address::SevenBit(0x2c), &mut bytes)
                        .unwrap();
                    assert_read(&bytes, 0x2c);
                }
            }
        }
        for access in &m.0.borrow().log {
            match access {
                Access::Write(offset, value) if COMMAND.contains(offset) => {
                    assert!((value & 15) <= 3);
                    assert_eq!(
                        (value >> 4) & 15,
                        COMMAND.iter().position(|x| x == offset).unwrap() as u32
                    );
                }
                Access::PayloadWrite(bytes) => {
                    assert!(bytes.len() <= INLINE);
                    assert_eq!(bytes, &output(bytes.len()));
                }
                Access::PayloadRead(length) => assert!(*length <= INLINE),
                _ => {}
            }
        }
        h.disable(bus(0)).unwrap();
        assert!(h.is_enabled(bus(1)));
        h.disable(bus(1)).unwrap();
        assert_eq!(m.0.borrow().enabled, [false; 2]);
        let owners = h.release().ok().unwrap();
        drop(owners);
        drop(m);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn inputs_refuse_without_io_and_speed_never_exceeds_observed_limit() {
        for id in [2, 255, u64::MAX] {
            assert_eq!(BusId::from_uid(id), Err(ErrorKind::Configuration));
        }
        let speeds = [
            (100_000, Speed::Khz100),
            (399_999, Speed::Khz100),
            (400_000, Speed::Khz400),
            (1_399_999, Speed::Mhz1),
            (1_400_000, Speed::Mhz1_4),
            (3_400_000, Speed::Mhz3_4),
        ];
        for (limit, speed) in speeds {
            assert_eq!(Speed::from_limit(limit), Ok(speed));
        }
        assert_eq!(Speed::from_limit(99_999), Err(ErrorKind::Configuration));
        let (mut h, m, _) = fixture();
        assert_eq!(
            h.write(bus(0), Address::SevenBit(0x15), &[1])
                .unwrap_err()
                .kind,
            ErrorKind::NotEnabled
        );
        for address in [
            Address::SevenBit(0),
            Address::SevenBit(0x78),
            Address::TenBit(0x15),
        ] {
            assert_eq!(
                h.write(bus(0), address, &[1]).unwrap_err().kind,
                ErrorKind::InvalidAddress
            );
        }
        for length in [0, 4096] {
            assert_eq!(
                h.write(bus(0), Address::SevenBit(0x15), &vec![0; length])
                    .unwrap_err()
                    .kind,
                ErrorKind::Length(length)
            );
        }
        assert!(m.0.borrow().log.is_empty());
        assert!(h.failure().is_none());
    }
    #[test]
    fn every_event_field_is_checked_before_caller_output_and_old_events_are_not_reused() {
        for bit in 0..32 {
            let (mut h, m, _) = fixture();
            h.enable(bus(0)).unwrap();
            m.0.borrow_mut().corrupt = 1 << bit;
            let mut out = [0xa5; 17];
            let error = h
                .read(bus(0), Address::SevenBit(0x2c), &mut out)
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Response, "bit{bit}");
            assert!(error.event.is_some());
            assert!(error.published);
            assert_eq!(out, [0xa5; 17]);
            let count = m.0.borrow().count;
            assert_eq!(h.enable(bus(1)).unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(count, m.0.borrow().count);
        }
        for id in 0..2 {
            let (mut h, m, _) = fixture();
            m.0.borrow_mut().events[id] = 0x1234;
            let error = h.enable(bus(0)).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Pending);
            assert_eq!(error.event, Some(0x1234));
            assert!(!error.published);
            assert!(
                m.0.borrow()
                    .log
                    .iter()
                    .all(|a| matches!(a, Access::Read(_)))
            );
        }
    }
    #[test]
    fn before_and_after_every_register_effect_fail_closed_for_both_buses_and_dma() {
        for length in [17, 33] {
            let (mut baseline, model, _) = fixture();
            baseline.enable(bus(0)).unwrap();
            model.0.borrow_mut().count = 0;
            model.0.borrow_mut().log.clear();
            let mut out = vec![0xa5; length];
            baseline
                .read(bus(0), Address::SevenBit(0x2c), &mut out)
                .unwrap();
            let total = model.0.borrow().count;
            for access in 1..=total {
                for after in [false, true] {
                    let (mut h, m, drops) = fixture();
                    h.enable(bus(0)).unwrap();
                    m.0.borrow_mut().count = 0;
                    m.0.borrow_mut().fail = Some((access, after));
                    let mut out = vec![0xa5; length];
                    let error = h
                        .read(bus(0), Address::SevenBit(0x2c), &mut out)
                        .unwrap_err();
                    assert_eq!(error.kind, ErrorKind::Io);
                    assert_eq!(out, vec![0xa5; length]);
                    let count = m.0.borrow().count;
                    assert_eq!(
                        h.write(bus(1), Address::SevenBit(0x15), &[1])
                            .unwrap_err()
                            .kind,
                        ErrorKind::NeedsReset
                    );
                    assert_eq!(count, m.0.borrow().count);
                    assert_eq!(h.failure(), Some(error));
                    drop(h);
                    drop(m);
                    assert_eq!(drops.get(), 0, "uncertain actual owner was freed");
                }
            }
        }
    }
    #[test]
    fn late_reads_keep_the_actual_event_and_timeout_retains_payload_owners() {
        let (mut baseline, m, _) = fixture();
        baseline.enable(bus(0)).unwrap();
        m.0.borrow_mut().count = 0;
        m.0.borrow_mut().log.clear();
        let mut out = [0xa5; 17];
        baseline
            .read(bus(0), Address::SevenBit(0x2c), &mut out)
            .unwrap();
        let log = m.0.borrow().log.clone();
        for access in 1..=log.len() {
            let (mut h, m, _) = fixture();
            h.enable(bus(0)).unwrap();
            m.0.borrow_mut().count = 0;
            m.0.borrow_mut().late = Some(access);
            let mut out = [0xa5; 17];
            let error = h
                .read(bus(0), Address::SevenBit(0x2c), &mut out)
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout);
            assert_eq!(out, [0xa5; 17]);
            if matches!(log[access-1],Access::Read(offset) if offset==EVENT[0]) && access > 3 {
                assert_ne!(error.event, Some(0));
            }
            assert_eq!(h.failure(), Some(error));
        }
        let (mut h, m, _) = fixture();
        h.enable(bus(0)).unwrap();
        m.0.borrow_mut().hang = true;
        let mut out = [0xa5; 33];
        assert_eq!(
            h.read(bus(0), Address::SevenBit(0x2c), &mut out)
                .unwrap_err()
                .kind,
            ErrorKind::Timeout
        );
        assert_eq!(out, [0xa5; 33]);
    }
    #[test]
    fn enabled_drop_retains_actual_owner_and_normal_disable_allows_release() {
        let (mut h, m, drops) = fixture();
        h.enable(bus(1)).unwrap();
        drop(h);
        drop(m);
        assert_eq!(drops.get(), 0);
        let (mut h, m, drops) = fixture();
        h.enable(bus(1)).unwrap();
        h.disable(bus(1)).unwrap();
        drop(h);
        drop(m);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    #[ignore = "requires a fresh unchanged Linux source oracle trace"]
    fn unchanged_linux_source_commands_and_events() {
        extern crate std;
        let path = std::env::var("STELA_AMD_MP2_ORACLE").expect("STELA_AMD_MP2_ORACLE trace path");
        let trace = std::fs::read_to_string(path).unwrap();
        let (mut host, model, _) = fixture();
        let mut cases = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split(',').collect();
            let number = |index: usize| fields[index].parse::<usize>().unwrap();
            let hex = |index: usize| u64::from_str_radix(fields[index], 16).unwrap();
            if fields[0] == "E" {
                let (mut h, m, _) = fixture();
                h.enable(bus(0)).unwrap();
                let op = number(1);
                let event = hex(2) as u32;
                let expected = 1 | (op as u32 * 2) << 2 | 1 << 7 | 17 << 12 | 0x2c << 24;
                m.0.borrow_mut().corrupt = expected ^ event;
                let mut out = [0xa5; 17];
                let result = if op == 0 {
                    h.read(bus(0), Address::SevenBit(0x2c), &mut out)
                } else {
                    h.write(bus(0), Address::SevenBit(0x2c), &output(17))
                };
                let source_accepts = number(3) != 0;
                let correlated = (event >> 8) & 15 == 0 && (event >> 7) & 1 == 1;
                assert_eq!(result.is_ok(), source_accepts && correlated);
                if result.is_err() {
                    assert_eq!(out, [0xa5; 17]);
                }
            } else {
                let id = number(1);
                let speed = number(2);
                host.speeds[id] = Some(
                    [
                        Speed::Khz100,
                        Speed::Khz400,
                        Speed::Mhz1,
                        Speed::Mhz1_4,
                        Speed::Mhz3_4,
                    ][speed],
                );
                if fields[0] == "P" {
                    let enable = number(3) != 0;
                    if !enable && !host.is_enabled(bus(id as u64)) {
                        host.enable(bus(id as u64)).unwrap();
                    }
                    model.0.borrow_mut().log.clear();
                    if enable {
                        host.enable(bus(id as u64)).unwrap();
                    } else {
                        host.disable(bus(id as u64)).unwrap();
                    }
                    let command = model
                        .0
                        .borrow()
                        .log
                        .iter()
                        .find_map(|access| match access {
                            Access::Write(offset, word) if *offset == COMMAND[id] => Some(*word),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(u64::from(command), hex(4));
                } else {
                    let op = number(3);
                    let length = number(4);
                    model.0.borrow_mut().log.clear();
                    if op == 0 {
                        let mut bytes = vec![0xa5; length];
                        host.read(bus(id as u64), Address::SevenBit(0x2c), &mut bytes)
                            .unwrap();
                        assert_read(&bytes, 0x2c);
                    } else {
                        host.write(bus(id as u64), Address::SevenBit(0x2c), &output(length))
                            .unwrap();
                    }
                    let d = model.0.borrow();
                    let command = d
                        .log
                        .iter()
                        .find_map(|access| match access {
                            Access::Write(offset, word) if *offset == COMMAND[id] => Some(*word),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(u64::from(command), hex(5));
                    if length > INLINE {
                        assert_eq!(hex(6), 0x123456789abcdef0);
                        assert_eq!(d.address, host.owners.as_ref().unwrap().2.physical());
                    } else if op == 1 {
                        let actual = output(length);
                        let mut first = [0; 8];
                        let count = length.min(8);
                        first[..count].copy_from_slice(&actual[..count]);
                        assert_eq!(u64::from_le_bytes(first), hex(6));
                    } else {
                        assert_eq!(hex(6), 0);
                    }
                }
            }
            cases += 1;
        }
        assert_eq!(cases, 90112);
        for id in 0..2 {
            host.disable(bus(id)).unwrap();
        }
    }

    #[test]
    fn write_and_power_faults_fence_both_buses_and_never_replay_a_command() {
        fn setup(case: usize) -> (Host, Model, Rc<Cell<usize>>) {
            let (mut h, m, drops) = fixture();
            h.enable(bus(1)).unwrap();
            if case != 0 {
                h.enable(bus(0)).unwrap();
            }
            m.0.borrow_mut().count = 0;
            m.0.borrow_mut().log.clear();
            (h, m, drops)
        }
        fn run(h: &mut Host, case: usize) -> Result<(), Error> {
            match case {
                0 => h.enable(bus(0)),
                1 => h.disable(bus(0)),
                2 => h.write(bus(0), Address::SevenBit(0x2c), &output(17)),
                3 => h.write(bus(0), Address::SevenBit(0x2c), &output(33)),
                _ => unreachable!(),
            }
        }
        for case in 0..4 {
            let (mut baseline, m, _) = setup(case);
            run(&mut baseline, case).unwrap();
            let total = m.0.borrow().count;
            for index in 1..=total {
                for after in [false, true] {
                    let (mut h, m, drops) = setup(case);
                    m.0.borrow_mut().fail = Some((index, after));
                    let error = run(&mut h, case).unwrap_err();
                    assert_eq!(error.kind, ErrorKind::Io);
                    assert_eq!(h.failure(), Some(error));
                    let count = m.0.borrow().count;
                    assert_eq!(h.disable(bus(1)).unwrap_err().kind, ErrorKind::NeedsReset);
                    assert_eq!(m.0.borrow().count, count);
                    drop(h);
                    drop(m);
                    assert_eq!(drops.get(), 0);
                }
            }
        }
    }
    #[test]
    fn invalid_claim_returns_the_actual_owned_resources_without_io() {
        let (host, m, _) = fixture();
        let (r, t, buffer) = host.release().ok().unwrap();
        let physical = buffer.physical();
        // SAFETY: same real private stopped model and RAM ownership as fixture;
        // deliberately invalid scalar config must be rejected without publication.
        let (kind, (r, _t, buffer)) = unsafe { Controller::claim(r, t, buffer, [None, None], 100) }
            .err()
            .unwrap();
        assert_eq!(kind, ErrorKind::Configuration);
        assert_eq!(buffer.physical(), physical);
        assert!(Rc::ptr_eq(&r.0, &m.0));
        assert!(m.0.borrow().log.is_empty());
    }
}
