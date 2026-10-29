// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Read-only PCH NVM banks and the hardware flash sequencing engine.
//! No erase/program/checksum-repair command is issued. Missing valid banks and
//! family-required checksums fail explicitly instead of falling back to bank
//! zero. ID-selected TGP/ADP validation follows its source marker policy.
use super::Delay;
use alloc::{boxed::Box, vec::Vec};

const GFPREG: u32 = 0;
const HSFSTS: u32 = 4;
const HSFCTL: u32 = 6;
const FADDR: u32 = 8;
const FDATA: u32 = 16;
const STRAP: u32 = 0xc;
const FWSM: u32 = 0x5b54;
const DONE: u16 = 1;
const CYCLE_ERROR: u16 = 1 << 1;
const ACCESS_ERROR: u16 = 1 << 2;
const IN_PROGRESS: u16 = 1 << 5;
const DESCRIPTOR_VALID: u16 = 1 << 14;
const GO: u16 = 1;
const CYCLE_MASK: u16 = 3 << 1;
const SIZE_MASK: u16 = 3 << 8;
const POLLS: usize = 10_000_000;
const REPEATS: usize = 10;
const WORD_LIMIT: u32 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    Pch2,
    Lpt,
    Spt,
}
/// Private PCI-family policies selected by the cold I219 constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum I219Validation {
    Tgp,
    Adp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CycleFailure {
    Timeout,
    Status(u16),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Removed,
    FirmwareOwned,
    InvalidGeometry,
    InvalidDescriptor,
    Bounds,
    Allocation,
    Busy,
    Timeout,
    Cycle(u16),
    Followup {
        primary: CycleFailure,
        observation: Box<Error>,
    },
    NoValidBank,
    Checksum(u16),
    RepairRequired,
    InvalidStation,
    Poisoned,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCH NVM: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Serialized access to this PCH MAC and its flash-register window.
///
/// # Safety
/// The implementation keeps the real exclusive powered PCI reservation and
/// UC mappings, excluding firmware/SMM, other drivers, workers and resets from
/// the complete hardware sequencer and NVM for its entire lifetime. MAC reads
/// and flash width-specific accesses are real bounded/aligned little-endian
/// volatile operations; reads flush this function's posted writes. Errors do
/// not invent observations or acknowledged stores. Existing native DMA/IRQs
/// are drained before granting access. The flash window is the separate
/// flash BAR on PCH2/LPT or MAC BAR+0xe000 on SPT, not a guessed physical cast.
pub unsafe trait Registers: 'static {
    fn read_mac32(&mut self, offset: u32) -> Result<u32, Error>;
    fn read16(&mut self, offset: u32) -> Result<u16, Error>;
    fn read32(&mut self, offset: u32) -> Result<u32, Error>;
    fn write16(&mut self, offset: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub base: u32,
    pub bank_words: u32,
}
impl Geometry {
    fn from_register(layout: Layout, value: u32) -> Result<Self, Error> {
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        let (base, bytes) = if layout == Layout::Spt {
            (0, (((value >> 1) & 31) + 1) * 4096)
        } else {
            let first = value & 0x1fff;
            let end = ((value >> 16) & 0x1fff) + 1;
            if end <= first {
                return Err(Error::InvalidGeometry);
            }
            (first << 12, (end - first) << 12)
        };
        let bank_words = bytes / 4;
        if bank_words < 64 || base.checked_add(bytes).is_none_or(|end| end > 0x0100_0000) {
            return Err(Error::InvalidGeometry);
        }
        Ok(Self { base, bank_words })
    }
}

pub struct Nvm<R: Registers, D: Delay> {
    io: Option<R>,
    delay: D,
    layout: Layout,
    geometry: Geometry,
    bank: Option<u8>,
    poisoned: bool,
}
impl<R: Registers, D: Delay> Nvm<R, D> {
    /// # Safety
    /// `layout` comes from the live PCH PCI generation, not a guessed
    /// family match. `io` and `delay` satisfy the device/resource and
    /// minimum elapsed-time contracts; the caller has a fresh exclusive reset
    /// epoch. NVM is immutable except for this owner's read-only sequencing.
    /// No failed access epoch is reconstructed without real reset/recovery.
    pub unsafe fn new(layout: Layout, io: R, delay: D) -> Result<Self, Error> {
        let mut this = Self {
            io: Some(io),
            delay,
            layout,
            geometry: Geometry {
                base: 0,
                bank_words: 0,
            },
            bank: None,
            poisoned: false,
        };
        let result = (|| {
            let fw = this.io().read_mac32(FWSM)?;
            if fw == u32::MAX {
                return Err(Error::Removed);
            }
            if fw & (1 << 15) != 0 {
                return Err(Error::FirmwareOwned);
            }
            let value = if layout == Layout::Spt {
                this.io().read_mac32(STRAP)?
            } else {
                this.io().read32(GFPREG)?
            };
            this.geometry = Geometry::from_register(layout, value)?;
            Ok(())
        })();
        if let Err(error) = result {
            this.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    fn io(&mut self) -> &mut R {
        self.io.as_mut().expect("retained NVM register owner")
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn selected_bank(&self) -> Option<u8> {
        self.bank
    }
    fn status(&mut self) -> Result<u16, Error> {
        let value = self.io().read16(HSFSTS)?;
        if value == u16::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn status_write(&mut self, value: u16) -> Result<(), Error> {
        if self.layout == Layout::Spt {
            self.io().write32(HSFSTS, u32::from(value))
        } else {
            self.io().write16(HSFSTS, value)
        }
    }
    fn control(&mut self) -> Result<u16, Error> {
        let value = if self.layout == Layout::Spt {
            self.io().read32(HSFSTS)? >> 16
        } else {
            u32::from(self.io().read16(HSFCTL)?)
        };
        if value == u32::from(u16::MAX) {
            Err(Error::Removed)
        } else {
            Ok(value as u16)
        }
    }
    fn control_write(&mut self, value: u16) -> Result<(), Error> {
        if self.layout == Layout::Spt {
            self.io().write32(HSFSTS, u32::from(value) << 16)
        } else {
            self.io().write16(HSFCTL, value)
        }
    }
    fn initialize_cycle(&mut self) -> Result<(), Error> {
        let mut status = self.status()?;
        if status & DESCRIPTOR_VALID == 0 {
            return Err(Error::InvalidDescriptor);
        }
        status |= CYCLE_ERROR | ACCESS_ERROR;
        self.status_write(status)?;
        if status & IN_PROGRESS != 0 {
            let mut idle = false;
            for _ in 0..POLLS {
                status = self.status()?;
                if status & IN_PROGRESS == 0 {
                    idle = true;
                    break;
                }
                self.delay.delay(1);
            }
            if !idle {
                return Err(Error::Busy);
            }
        }
        self.status_write(status | DONE)
    }
    fn start_cycle(&mut self) -> Result<(), Error> {
        let control = self.control()?;
        self.control_write(control | GO)?;
        for _ in 0..=POLLS {
            let status = self.status()?;
            if status & DONE != 0 {
                return if status & (CYCLE_ERROR | ACCESS_ERROR) == 0 {
                    Ok(())
                } else {
                    Err(Error::Cycle(status))
                };
            }
            self.delay.delay(1);
        }
        Err(Error::Timeout)
    }
    fn read_cycle(&mut self, offset: u32, size: u8) -> Result<u32, Error> {
        let region_bytes = self
            .geometry
            .bank_words
            .checked_mul(4)
            .ok_or(Error::Bounds)?;
        if !matches!(size, 1 | 2 | 4)
            || (self.layout == Layout::Spt) != (size == 4)
            || offset
                .checked_add(u32::from(size))
                .is_none_or(|end| end > region_bytes)
        {
            return Err(Error::Bounds);
        }
        let address = self
            .geometry
            .base
            .checked_add(offset)
            .ok_or(Error::Bounds)?;
        for attempt in 0..=REPEATS {
            self.delay.delay(1);
            self.initialize_cycle()?;
            let control =
                (self.control()? & !(CYCLE_MASK | SIZE_MASK)) | (u16::from(size - 1) << 8);
            self.control_write(control)?;
            self.io().write32(FADDR, address)?;
            match self.start_cycle() {
                Ok(()) => {
                    return self.io().read32(FDATA).map(|value| match size {
                        1 => value & 0xff,
                        2 => value & 0xffff,
                        _ => value,
                    });
                }
                Err(error @ (Error::Cycle(_) | Error::Timeout)) => {
                    let status = self.status().map_err(|observation| Error::Followup {
                        primary: match &error {
                            Error::Timeout => CycleFailure::Timeout,
                            Error::Cycle(status) => CycleFailure::Status(*status),
                            _ => unreachable!("matched cycle failure"),
                        },
                        observation: Box::new(observation),
                    })?;
                    if status & CYCLE_ERROR != 0 && attempt < REPEATS {
                        continue;
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded retry loop always returns")
    }
    fn bank(&mut self) -> Result<u8, Error> {
        if let Some(bank) = self.bank {
            return Ok(bank);
        }
        let bank_bytes = self.geometry.bank_words * 2;
        for bank in 0..2 {
            let signature = if self.layout == Layout::Spt {
                (self.read_cycle(bank * bank_bytes + 0x13 * 2, 4)? >> 8) as u8
            } else {
                self.read_cycle(bank * bank_bytes + 0x13 * 2 + 1, 1)? as u8
            };
            if signature & 0xc0 == 0x80 {
                self.bank = Some(bank as u8);
                return Ok(bank as u8);
            }
        }
        Err(Error::NoValidBank)
    }
    fn read_inner(&mut self, offset: u16, output: &mut [u16]) -> Result<(), Error> {
        let bank = u32::from(self.bank()?);
        let first = bank * self.geometry.bank_words + u32::from(offset);
        if self.layout == Layout::Spt {
            for i in (0..output.len()).step_by(2) {
                let at = first + i as u32;
                if output.len() - i == 1 {
                    let data = self.read_cycle((at & !1) * 2, 4)?;
                    output[i] = (data >> ((at & 1) * 16)) as u16;
                } else {
                    let data = self.read_cycle(at * 2, 4)?;
                    output[i] = data as u16;
                    output[i + 1] = (data >> 16) as u16;
                }
            }
        } else {
            for (index, value) in output.iter_mut().enumerate() {
                *value = self.read_cycle((first + index as u32) * 2, 2)? as u16;
            }
        }
        Ok(())
    }
    pub fn read(&mut self, offset: u16, output: &mut [u16]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let limit = self.geometry.bank_words.min(WORD_LIMIT) as usize;
        if output.is_empty()
            || usize::from(offset)
                .checked_add(output.len())
                .is_none_or(|end| end > limit)
        {
            return Err(Error::Bounds);
        }
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(output.len())
            .map_err(|_| Error::Allocation)?;
        staged.resize(output.len(), 0);
        match self.read_inner(offset, &mut staged) {
            Ok(()) => {
                output.copy_from_slice(&staged);
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    /// Validate the factory checksum and source generation's validity marker.
    /// An image needing persistent repair is an explicit unsupported profile.
    pub fn validate(&mut self) -> Result<(), Error> {
        let mut words = [0u16; 64];
        self.read(0, &mut words)?;
        let sum = words.iter().copied().fold(0u16, u16::wrapping_add);
        let (at, mask) = if self.layout == Layout::Pch2 {
            (0x19, 0x40)
        } else {
            (3, 1)
        };
        let result = if words[at] & mask == 0 {
            Err(Error::RepairRequired)
        } else if sum != 0xbaba {
            Err(Error::Checksum(sum))
        } else {
            Ok(())
        };
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Source TGP/ADP checksum policy after PCI family selection. The
    /// selected bank is still observed by `read`; station validity is separate.
    /// TGP alone skips the checksum when its NVM compatibility marker
    /// is clear, or accepts its successfully read uninitialized checksum word.
    /// ADP always checks the checksum and does not demand repair.
    pub(super) fn validate_i219(&mut self, family: I219Validation) -> Result<(), Error> {
        if self.layout != Layout::Spt {
            self.poisoned = true;
            return Err(Error::InvalidGeometry);
        }
        let mut marker = [0u16; 1];
        self.read(3, &mut marker)?;
        if family == I219Validation::Tgp && marker[0] & 1 == 0 {
            return Ok(());
        }
        let mut words = [0u16; 64];
        self.read(0, &mut words)?;
        // The unchanged generic source validator also exempts an explicitly
        // uninitialized TGP checksum word. No other family gets that rule.
        if family == I219Validation::Tgp && words[63] == u16::MAX {
            return Ok(());
        }
        let sum = words.iter().copied().fold(0u16, u16::wrapping_add);
        if sum != 0xbaba {
            self.poisoned = true;
            return Err(Error::Checksum(sum));
        }
        Ok(())
    }
    pub fn station(&mut self) -> Result<crate::net::Mac, Error> {
        let mut words = [0u16; 3];
        self.read(0, &mut words)?;
        let mut bytes = [0u8; 6];
        for (to, word) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(words) {
            *to = word.to_le_bytes();
        }
        let mac = crate::net::Mac(bytes);
        if bytes == [0; 6] || bytes == [0xff; 6] || mac.is_multicast() {
            self.poisoned = true;
            Err(Error::InvalidStation)
        } else {
            Ok(mac)
        }
    }
}
impl<R: Registers, D: Delay> Drop for Nvm<R, D> {
    fn drop(&mut self) {
        if self.poisoned
            && let Some(owner) = self.io.take()
        {
            // Keep the claim and mappings after uncertain flash state.
            core::mem::forget(owner);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{rc::Rc, sync::Arc, vec, vec::Vec};
    use core::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct State {
        layout: Layout,
        fw: u32,
        gfpreg: u32,
        strap: u32,
        memory: Vec<u8>,
        status: u16,
        control: u16,
        address: u32,
        data: u32,
        ops: Vec<[u32; 3]>,
        accesses: usize,
        fail_at: Option<usize>,
        errors: usize,
        delay_reads: usize,
        pending: Option<usize>,
        hang: bool,
        record: bool,
        reads: usize,
        waits: usize,
        cycles: usize,
    }
    impl State {
        fn record(&mut self, kind: u32, address: u32, value: u32) {
            if self.record {
                self.ops.push([kind, address, value]);
            }
        }
        fn enter(&mut self) -> Result<(), Error> {
            let at = self.accesses;
            self.accesses += 1;
            if self.fail_at == Some(at) {
                Err(Error::Access)
            } else {
                Ok(())
            }
        }
        fn status(&mut self) -> u16 {
            self.reads += 1;
            if let Some(left) = self.pending
                && !self.hang
            {
                if left == 0 {
                    self.pending = None;
                    self.status = (self.status & !IN_PROGRESS) | DONE;
                    if self.errors > 0 {
                        self.errors -= 1;
                        self.status |= CYCLE_ERROR;
                    }
                } else {
                    self.pending = Some(left - 1);
                }
            }
            self.status
        }
        fn status_store(&mut self, value: u16) {
            self.status &= !(value & (DONE | CYCLE_ERROR | ACCESS_ERROR));
        }
        fn control_store(&mut self, value: u16) {
            self.control = value & !GO;
            if value & GO != 0 {
                assert_eq!(
                    value & CYCLE_MASK,
                    0,
                    "persistent flash modification attempted"
                );
                self.cycles += 1;
                self.pending = Some(self.delay_reads);
                self.status = (self.status & !(DONE | CYCLE_ERROR | ACCESS_ERROR)) | IN_PROGRESS;
                let size = usize::from((value & SIZE_MASK) >> 8) + 1;
                let at = self.address as usize;
                let mut bytes = [0xf0u8; 4];
                bytes[..size].copy_from_slice(&self.memory[at..at + size]);
                self.data = u32::from_le_bytes(bytes);
            }
        }
    }
    struct Io {
        state: Rc<RefCell<State>>,
        released: Arc<AtomicUsize>,
    }
    impl Drop for Io {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }
    // SAFETY: one serial deterministic register/flash model with no concurrent
    // native producer; flash operations are not performed by this fixture.
    unsafe impl Registers for Io {
        fn read_mac32(&mut self, at: u32) -> Result<u32, Error> {
            let mut s = self.state.borrow_mut();
            s.enter()?;
            let value = match at {
                FWSM => s.fw,
                STRAP => s.strap,
                _ => panic!("unknown MAC read"),
            };
            s.record(0x10, at, value);
            Ok(value)
        }
        fn read16(&mut self, at: u32) -> Result<u16, Error> {
            let mut s = self.state.borrow_mut();
            s.enter()?;
            let value = match at {
                HSFSTS => s.status(),
                HSFCTL => {
                    assert_ne!(s.layout, Layout::Spt);
                    s.control
                }
                _ => panic!("unknown read16"),
            };
            s.record(0, at, u32::from(value));
            Ok(value)
        }
        fn read32(&mut self, at: u32) -> Result<u32, Error> {
            let mut s = self.state.borrow_mut();
            s.enter()?;
            let value = match at {
                GFPREG => s.gfpreg,
                HSFSTS => {
                    assert_eq!(s.layout, Layout::Spt);
                    u32::from(s.status()) | (u32::from(s.control) << 16)
                }
                FDATA => s.data,
                _ => panic!("unknown read32"),
            };
            s.record(1, at, value);
            Ok(value)
        }
        fn write16(&mut self, at: u32, value: u16) -> Result<(), Error> {
            let mut s = self.state.borrow_mut();
            s.enter()?;
            assert_ne!(s.layout, Layout::Spt);
            s.record(2, at, u32::from(value));
            match at {
                HSFSTS => s.status_store(value),
                HSFCTL => s.control_store(value),
                _ => panic!("unknown write16"),
            };
            Ok(())
        }
        fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
            let mut s = self.state.borrow_mut();
            s.enter()?;
            s.record(3, at, value);
            match at {
                HSFSTS => {
                    assert_eq!(s.layout, Layout::Spt);
                    s.status_store(value as u16);
                    s.control_store((value >> 16) as u16)
                }
                FADDR => s.address = value,
                _ => panic!("unknown write32"),
            };
            Ok(())
        }
    }
    struct Timer(Rc<RefCell<State>>);
    impl Delay for Timer {
        fn delay(&mut self, us: u64) {
            let mut s = self.0.borrow_mut();
            s.waits += 1;
            s.record(4, us as u32, 0);
        }
    }
    fn make_state(layout: Layout, bank: u8) -> State {
        let base = if layout == Layout::Spt { 0 } else { 0x2000 };
        let mut memory = vec![0u8; base + 8192];
        for b in 0..2 {
            let mut words = [0u16; 2048];
            for (i, word) in words.iter_mut().enumerate() {
                *word = (i as u16).wrapping_mul(17) ^ ((b as u16) << 12);
            }
            words[0] = 0x1102;
            words[1] = 0x3322;
            words[2] = 0x5544;
            words[3] |= 1;
            words[0x19] |= 0x40;
            words[0x13] = (words[0x13] & 0x3fff) | if b == usize::from(bank) { 0x8000 } else { 0 };
            words[63] =
                0xbabau16.wrapping_sub(words[..63].iter().copied().fold(0, u16::wrapping_add));
            for (i, word) in words.into_iter().enumerate() {
                memory[base + b * 4096 + i * 2..base + b * 4096 + i * 2 + 2]
                    .copy_from_slice(&word.to_le_bytes());
            }
        }
        State {
            layout,
            fw: 0x40,
            gfpreg: (3 << 16) | 2,
            strap: 2,
            memory,
            status: DESCRIPTOR_VALID | DONE,
            control: 0x4400,
            address: 0,
            data: 0,
            ops: Vec::new(),
            accesses: 0,
            fail_at: None,
            errors: 0,
            delay_reads: 0,
            pending: None,
            hang: false,
            record: true,
            reads: 0,
            waits: 0,
            cycles: 0,
        }
    }
    type Fixture = (Nvm<Io, Timer>, Rc<RefCell<State>>, Arc<AtomicUsize>);
    fn fixture(layout: Layout, bank: u8) -> Fixture {
        let state = Rc::new(RefCell::new(make_state(layout, bank)));
        let released = Arc::new(AtomicUsize::new(0));
        let io = Io {
            state: state.clone(),
            released: released.clone(),
        };
        // SAFETY: one controlled fresh model matches its selected layout.
        let nvm = unsafe { Nvm::new(layout, io, Timer(state.clone())) }.unwrap();
        (nvm, state, released)
    }
    #[test]
    fn actual_geometries_and_banks_supply_validated_factory_station() {
        for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
            for bank in 0..2 {
                let (mut nvm, state, released) = fixture(layout, bank);
                assert_eq!(
                    nvm.geometry(),
                    Geometry {
                        base: if layout == Layout::Spt { 0 } else { 0x2000 },
                        bank_words: 2048
                    }
                );
                nvm.validate().unwrap();
                assert_eq!(nvm.selected_bank(), Some(bank));
                assert_eq!(nvm.station().unwrap().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert!(state.borrow().cycles > 0);
                drop(nvm);
                assert_eq!(released.load(Ordering::SeqCst), 1);
            }
        }
    }
    #[test]
    fn odd_spt_reads_and_erased_data_are_actual_bounded_payloads() {
        for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
            let (mut nvm, state, _) = fixture(layout, 1);
            let base = if layout == Layout::Spt { 0 } else { 0x2000 };
            state.borrow_mut().memory[base + 4096 + 7 * 2..base + 4096 + 7 * 2 + 2].fill(0xff);
            for (offset, length) in [(0, 1), (1, 2), (7, 5), (2046, 2), (2047, 1)] {
                let mut output = vec![0; length];
                nvm.read(offset, &mut output).unwrap();
                let s = state.borrow();
                for (i, word) in output.iter().enumerate() {
                    let at = base + 4096 + (usize::from(offset) + i) * 2;
                    assert_eq!(
                        *word,
                        u16::from_le_bytes(s.memory[at..at + 2].try_into().unwrap())
                    );
                }
            }
            assert!(!nvm.is_poisoned());
            let count = state.borrow().accesses;
            let mut unchanged = [0xdead; 2];
            assert_eq!(nvm.read(2047, &mut unchanged), Err(Error::Bounds));
            assert_eq!(unchanged, [0xdead; 2]);
            assert_eq!(state.borrow().accesses, count);
        }
    }
    #[test]
    fn every_flash_access_failure_preserves_output_and_retains_owner() {
        for layout in [Layout::Pch2, Layout::Spt] {
            let (mut good, state, _) = fixture(layout, 1);
            let begin = state.borrow().accesses;
            good.read(1, &mut [0u16; 3]).unwrap();
            let end = state.borrow().accesses;
            for fail in begin..end {
                let (mut nvm, state, released) = fixture(layout, 1);
                state.borrow_mut().fail_at = Some(fail);
                let mut output = [0xcafe; 3];
                assert_eq!(nvm.read(1, &mut output), Err(Error::Access));
                assert_eq!(output, [0xcafe; 3]);
                assert!(nvm.is_poisoned());
                let accesses = state.borrow().accesses;
                assert_eq!(nvm.read(0, &mut [0u16]), Err(Error::Poisoned));
                assert_eq!(state.borrow().accesses, accesses);
                drop(nvm);
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
    }
    #[test]
    fn invalid_bank_checksum_marker_and_descriptor_never_get_fallback_success() {
        for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
            for fault in 0..4 {
                let (mut nvm, state, _) = fixture(layout, 0);
                let base = if layout == Layout::Spt { 0 } else { 0x2000 };
                match fault {
                    0 => state.borrow_mut().memory[base + 0x13 * 2 + 1] = 0,
                    1 => state.borrow_mut().memory[base + 63 * 2] ^= 1,
                    2 => {
                        let at = if layout == Layout::Pch2 {
                            0x19 * 2
                        } else {
                            3 * 2
                        };
                        let mask = if layout == Layout::Pch2 { 0x40 } else { 1 };
                        state.borrow_mut().memory[base + at] &= !mask;
                    }
                    _ => state.borrow_mut().status &= !DESCRIPTOR_VALID,
                }
                let error = nvm.validate().unwrap_err();
                assert!(matches!(
                    (fault, error),
                    (0, Error::NoValidBank)
                        | (1, Error::Checksum(_))
                        | (2, Error::RepairRequired)
                        | (3, Error::InvalidDescriptor)
                ));
                assert!(nvm.is_poisoned());
            }
        }
    }
    #[test]
    fn retry_count_and_hung_completion_are_finite_and_do_not_program_flash() {
        for layout in [Layout::Pch2, Layout::Spt] {
            let (mut nvm, state, _) = fixture(layout, 0);
            state.borrow_mut().errors = 2;
            nvm.read(0, &mut [0u16]).unwrap();
            assert_eq!(state.borrow().cycles, 4);
            let (mut nvm, state, _) = fixture(layout, 0);
            state.borrow_mut().errors = 20;
            assert!(matches!(nvm.read(0, &mut [0u16]), Err(Error::Cycle(_))));
            assert_eq!(state.borrow().cycles, 11);
        }
        let (mut nvm, state, released) = fixture(Layout::Spt, 0);
        state.borrow_mut().hang = true;
        state.borrow_mut().record = false;
        let mut output = [0xaabb];
        assert_eq!(nvm.read(0, &mut output), Err(Error::Timeout));
        assert_eq!(output, [0xaabb]);
        assert_eq!(state.borrow().cycles, 1);
        assert_eq!(state.borrow().waits, POLLS + 2);
        drop(nvm);
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn a_failed_post_cycle_observation_keeps_the_actual_timeout() {
        let (mut baseline, state, _) = fixture(Layout::Spt, 0);
        state.borrow_mut().hang = true;
        state.borrow_mut().record = false;
        assert_eq!(baseline.read(0, &mut [0u16]), Err(Error::Timeout));
        let final_observation = state.borrow().accesses - 1;
        let (mut nvm, state, released) = fixture(Layout::Spt, 0);
        {
            let mut s = state.borrow_mut();
            s.hang = true;
            s.record = false;
            s.fail_at = Some(final_observation);
        }
        let mut untouched = [0xabcd];
        assert_eq!(
            nvm.read(0, &mut untouched),
            Err(Error::Followup {
                primary: CycleFailure::Timeout,
                observation: Box::new(Error::Access),
            })
        );
        assert_eq!(untouched, [0xabcd]);
        assert_eq!(state.borrow().cycles, 1);
        assert!(nvm.is_poisoned());
        drop(nvm);
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn geometry_and_me_qualification_refuse_without_sequencer_writes() {
        assert_eq!(
            Geometry::from_register(Layout::Pch2, 0x0001_0003),
            Err(Error::InvalidGeometry)
        );
        assert_eq!(
            Geometry::from_register(Layout::Pch2, u32::MAX),
            Err(Error::Removed)
        );
        for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
            let state = Rc::new(RefCell::new(make_state(layout, 0)));
            state.borrow_mut().fw |= 1 << 15;
            let released = Arc::new(AtomicUsize::new(0));
            let io = Io {
                state: state.clone(),
                released: released.clone(),
            };
            assert!(matches!(
                // SAFETY: sole model reservation, with the chosen layout.
                unsafe { Nvm::new(layout, io, Timer(state.clone())) },
                Err(Error::FirmwareOwned)
            ));
            assert!(!state.borrow().ops.iter().any(|op| matches!(op[0], 2 | 3)));
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn native_separate_and_integrated_windows_enforce_actual_access_widths() {
        use crate::net::e1000e::pch::io::NvmMmio;
        use core::ptr::NonNull;
        let mut mac = vec![0u32; 0x10000 / 4];
        let macp = NonNull::new(mac.as_mut_ptr().cast()).unwrap();
        let mut flash = vec![0u32; 8];
        let flashp = NonNull::new(flash.as_mut_ptr().cast()).unwrap();
        let owner: Arc<dyn core::any::Any> = Arc::new(());
        // SAFETY: exclusive stable allocations stand in for the two UC
        // windows in this model only; no physical-hardware proof is inferred.
        let mut separate =
            unsafe { NvmMmio::from_separate_windows(macp, 0x10000, flashp, 32, owner.clone()) }
                .unwrap();
        separate.write16(6, 0x1234).unwrap();
        assert_eq!(separate.read16(6).unwrap(), 0x1234);
        assert_eq!(flash[1], 0x1234_0000);
        assert_eq!(separate.write32(6, 0), Err(Error::Bounds));
        assert_eq!(separate.read16(31), Err(Error::Bounds));
        assert_eq!(separate.read32(32), Err(Error::Bounds));
        assert_eq!(flash[2], 0);
        drop(separate);
        // SAFETY: same-allocation +e000 subwindow and complete bounds.
        let mut integrated = unsafe { NvmMmio::from_mac_window(macp, 0x10000, owner) }.unwrap();
        integrated.write32(4, 0x5678_0000).unwrap();
        assert_eq!(integrated.read32(4).unwrap(), 0x5678_0000);
        assert_eq!(mac[(0xe000 + 4) / 4], 0x5678_0000);
        assert_eq!(mac[(0xe000 + 8) / 4], 0);
        assert_eq!(integrated.read16(0x2000), Err(Error::Bounds));
    }

    #[test]
    #[ignore = "oracle: STELA_E1000E_PCH_NVM_ORACLE"]
    fn unchanged_linux_pch_nvm_register_effects_and_payloads() {
        let path = std::env::var("STELA_E1000E_PCH_NVM_ORACLE").expect("NVM oracle trace");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len() % 4, 0);
        let words: Vec<u32> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b))
            .collect();
        let mut at = 0;
        let mut cases = 0;
        while at < words.len() {
            let h = &words[at..at + 8];
            at += 8;
            let layout = match h[0] {
                0 => Layout::Pch2,
                1 => Layout::Lpt,
                2 => Layout::Spt,
                _ => panic!("bad layout"),
            };
            let (mut nvm, state, _) = fixture(layout, h[1] as u8);
            {
                let mut s = state.borrow_mut();
                s.errors = h[4] as usize;
                s.delay_reads = h[5] as usize;
                if h[6] != 0 {
                    s.pending = Some(s.delay_reads);
                    s.status |= IN_PROGRESS;
                }
            }
            let expected = &words[at..at + h[3] as usize];
            at += h[3] as usize;
            let mut output = vec![0u16; h[3] as usize];
            nvm.read(h[2] as u16, &mut output).unwrap();
            assert_eq!(
                output.iter().copied().map(u32::from).collect::<Vec<_>>(),
                expected
            );
            let operations = words[at..at + h[7] as usize * 3].as_chunks::<3>().0;
            at += h[7] as usize * 3;
            assert_eq!(state.borrow().ops, operations, "case {cases}: {h:?}");
            cases += 1;
        }
        assert_eq!(cases, 648);
    }
}
