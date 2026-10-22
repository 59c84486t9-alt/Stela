// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C firmware reset, reserved-page transfer, IDDMA and actual ready
//! polling, adapted from pinned rtw88/{mac,fw,util}.c. The lower native beacon
//! TXBD queue is an explicit dependency. Downloaded firmware is not a radio:
//! HCI setup, OTP, calibration, channel, MLME and keys are separate operations.
use super::{
    firmware::{ParseError, Rtw88},
    identity::{Chip, Profile, Staged},
};
use crate::{Clock, bus::mmio::Mmio};
use alloc::sync::Arc;
use core::ptr::NonNull;

const MCU: u32 = 0x80;
const DDMA_SOURCE: u32 = 0x1200;
const DDMA_DEST: u32 = 0x1204;
const DDMA_CTRL: u32 = 0x1208;
const OWN: u32 = 1 << 31;
const CHECKSUM_ENABLE: u32 = 1 << 29;
const CHECKSUM_BAD: u32 = 1 << 27;
const CHECKSUM_RESET: u32 = 1 << 25;
const CHECKSUM_CONTINUE: u32 = 1 << 24;
const TX_BUFFER_PAYLOAD: u32 = 0x1878_0000 + 48;
const IMEM_BOUNDARY: u32 = 0x0020_0000;
const FIFO_PAGE: u32 = 0x204;
const BEACON_CTRL: u32 = 0x550;
const TXQ_CTRL: u32 = 0x422;
const CR_HIGH: u32 = 0x101;
const BCN_VALID: u16 = 1 << 15;
const LTE_CTRL: u32 = 0x1700;
const LTE_WRITE: u32 = 0x1704;
const LTE_READ: u32 = 0x1708;
const FW_READY: u32 = 0xc078;
const FW_READY_MASK: u32 = 0xcfff;
const MAX_POLLS: usize = 1000;
const CHUNK: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidState,
    WrongChip,
    WrongFirmwareTarget,
    InvalidBoundary,
    InvalidClock,
    Register,
    Queue,
    Timeout { register: u32, mask: u32 },
    Checksum { destination: u32 },
    DownloadChecksums,
    InvalidFirmwareKey,
    FirmwareNotReady { debug: u32 },
    HardwareFeatureId { observed: u8 },
    HardwareFeatureFirmwareNotReady { observed: u16 },
}

#[derive(Debug)]
pub enum StartError {
    Hardware(Error),
    Format(ParseError),
}
impl From<Error> for StartError {
    fn from(error: Error) -> Self {
        Self::Hardware(error)
    }
}

/// One native beacon TXBD queue, never a firmware or OS compatibility shim.
///
/// # Safety
/// The queue must belong to the exact RTL8822C PCI requester whose exclusive
/// UC BAR is passed to `NativeIo`. It must build the donor's 48-byte reserved
/// page TX descriptor and actual beacon TXBD using canonical pinned memory
/// and requester-specific DMA mappings, then ring PCI beacon work. The caller
/// owns no DMA allocation: the implementation copies `data` before returning
/// and retains descriptor/payload mappings through actual DMA completion or
/// acknowledged requester stop. Success means submission, not completion.
/// Errors may follow publication; Drop and quarantine must retain every
/// potentially live DMA resource and its claim until acknowledged quiescence.
pub unsafe trait BeaconQueue {
    fn submit(&mut self, data: &[u8]) -> Result<(), Error>;
    /// # Safety
    /// The actual FIFO_PAGE BCN_VALID was cleared before this submission,
    /// then observed newly set after it, with exclusive requester ownership.
    /// The device copied this reserved page and no longer reads its host
    /// payload/descriptor. This does not authorize unmapping the queue base.
    unsafe fn consumed(&mut self) -> Result<(), Error>;
    fn quarantine(&mut self);
}

/// Exact register access plus native reserved-page TX submission.
///
/// # Safety
/// All reads must be actual volatile observations of the selected, exclusively
/// owned RTL8822C requester; stores must complete in program order. No other
/// reset/IRQ/firmware worker may touch it during download. Never substitute
/// cached readiness or manufactured completion. `submit_beacon` follows the
/// `BeaconQueue` ownership contract; quarantine retains all uncertain DMA,
/// requester and BAR ownership. Delays must wait at least the requested time.
pub unsafe trait Io {
    /// Actual requester observation retained when acquiring this interface.
    fn profile(&self) -> Profile;
    fn read8(&mut self, register: u32) -> Result<u8, Error>;
    fn read16(&mut self, register: u32) -> Result<u16, Error>;
    fn read32(&mut self, register: u32) -> Result<u32, Error>;
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error>;
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn delay_us(&mut self, microseconds: u64);
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error>;
    /// # Safety
    /// Same actual new BCN_VALID completion proof as BeaconQueue::consumed.
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error>;
    fn quarantine(&mut self);
}

/// Real volatile MMIO and the native beacon queue. The BAR owner is retained
/// with the queue on any uncertain download; dropping this adapter cannot
/// unmap memory still accessible to a quarantined device.
pub struct NativeIo<Q: BeaconQueue> {
    registers: Mmio,
    clock: Clock,
    profile: Profile,
    bytes: usize,
    owned: Option<(Q, Arc<dyn core::any::Any>)>,
}
impl<Q: BeaconQueue> NativeIo<Q> {
    /// Access the retained native queue for later HCI setup and acknowledged
    /// stop/unmap. Queue methods still enforce their own ownership contracts;
    /// a quarantined download never returns its retained queue this way.
    pub fn beacon_queue(&mut self) -> Result<&mut Q, Error> {
        Ok(&mut self.owned.as_mut().ok_or(Error::InvalidState)?.0)
    }
    /// # Safety
    /// `window` is the actual RTL8822C exclusive uncached BAR, at least 0x170c
    /// bytes. `owner` retains the real PCI claim and mapped BAR reservation
    /// through its final Drop. `queue` is configured on that exact requester.
    /// Device MAC power and validated FIFO page layout must already be set;
    /// all competing DMA/IRQ/reset workers are stopped for this object's life.
    /// The clock is calibrated against the native host timer for this CPU.
    /// `profile` contains observations read from this exact requester, not a
    /// marketing/device-ID substitute or another adapter's firmware target.
    pub unsafe fn new(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, Error> {
        // SAFETY: caller supplies mapped exclusive UC requester ownership;
        // this entry additionally requires completed prior MAC power setup.
        unsafe { Self::mapped(window, bytes, queue, owner, clock, profile) }
    }
    /// Construct the real native interface and execute the source MAC power
    /// sequence before firmware download. No FIFO/HCI/radio readiness implied.
    ///
    /// # Safety
    /// Same real UC BAR/requester/profile/clock ownership as `new`, except MAC
    /// power may be off or left on by prior firmware. All old DMA/IRQ workers
    /// are acknowledged stopped and drained; the native beacon queue is
    /// fresh/idle, its isolated domain owns all mappings and no competing
    /// power/reset path exists. Caller retains validated FIFO geometry for
    /// the later source MAC configuration and download restore boundary.
    /// After this sequence, actual HCI/beacon-base reconfiguration/readback
    /// is required before Download or queue submission. The software queue's
    /// configured flag is not evidence that its base survived a power cycle.
    pub unsafe fn power_on_new(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, super::power::Error> {
        // SAFETY: caller supplies the actual exclusive mapped requester.
        let mut io = unsafe { Self::mapped(window, bytes, queue, owner, clock, profile)? };
        // SAFETY: entry contract requires independent stop/drain and fresh
        // idle queue, not a manufactured reset/firmware completion proof.
        unsafe { super::power::on(&mut io)? };
        Ok(io)
    }
    /// # Safety
    /// Actual exclusive UC BAR, owned requester, calibrated clock and exact
    /// observed profile. This mapping helper makes no MAC power-state claim.
    unsafe fn mapped(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, Error> {
        if bytes < 0x170c || window.as_ptr().addr() & 3 != 0 {
            return Err(Error::Register);
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::InvalidClock);
        }
        if profile.chip() != Chip::Rtl8822C {
            return Err(Error::WrongChip);
        }
        Ok(Self {
            // SAFETY: the constructor's actual UC BAR/ownership contract.
            registers: unsafe { Mmio::new(window.as_ptr() as u64) },
            clock,
            profile,
            bytes,
            owned: Some((queue, owner)),
        })
    }
    fn check(&self, register: u32, width: usize) -> Result<(), Error> {
        if self.owned.is_none()
            || !(register as usize).is_multiple_of(width)
            || (register as usize)
                .checked_add(width)
                .is_none_or(|end| end > self.bytes)
        {
            return Err(Error::Register);
        }
        Ok(())
    }
}
// SAFETY: constructor binds the actual exclusive BAR and native beacon queue.
// Each register operation is a volatile store/load, with no readiness cache.
unsafe impl<Q: BeaconQueue> Io for NativeIo<Q> {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        self.check(register, 1)?;
        Ok(self.registers.read8(register as usize))
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        self.check(register, 2)?;
        Ok(self.registers.read16(register as usize))
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        self.check(register, 4)?;
        Ok(self.registers.read32(register as usize))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        self.check(register, 1)?;
        self.registers.write8(register as usize, value);
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        self.check(register, 2)?;
        self.registers.write16(register as usize, value);
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.check(register, 4)?;
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.clock.delay(microseconds);
    }
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
        self.owned
            .as_mut()
            .ok_or(Error::InvalidState)?
            .0
            .submit(data)
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
        // SAFETY: caller supplies the new actual BCN_VALID completion proof;
        // constructor binds this queue to the exact exclusive requester/BAR.
        unsafe { self.owned.as_mut().ok_or(Error::InvalidState)?.0.consumed() }
    }
    fn quarantine(&mut self) {
        if let Some((queue, owner)) = self.owned.take() {
            let mut retained = core::mem::ManuallyDrop::new((queue, owner));
            retained.0.quarantine();
            // No ACKed requester stop exists. Retain queue plus its real BAR
            // claim indefinitely; clearing MCU enable is not DMA quiescence.
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Quarantined,
    /// Actual MCU ready observed; HCI index reset and radio setup remain.
    FirmwareReady,
}

/// Single download attempt. Any error after hardware mutation is terminal;
/// neither register restoration nor a firmware ready bit proves DMA stopped.
pub struct Download<I: Io> {
    io: I,
    boundary: u16,
    state: State,
    feature_requested: bool,
}
impl<I: Io> Download<I> {
    /// `boundary` is the actual validated RTL8822C FIFO reserved-page boundary,
    /// established by prior MAC initialization, not an invented default.
    pub fn new(io: I, boundary: u16) -> Result<Self, Error> {
        if boundary > 0x7ff {
            return Err(Error::InvalidBoundary);
        }
        Ok(Self {
            io,
            boundary,
            state: State::Idle,
            feature_requested: false,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Continue actual native HCI/radio initialization only after the exact
    /// MCU ready status was observed. This grants no Ethernet/carrier state.
    pub fn after_firmware_ready(&mut self) -> Result<&mut I, Error> {
        if self.state != State::FirmwareReady || self.feature_requested {
            return Err(Error::InvalidState);
        }
        Ok(&mut self.io)
    }
    pub fn start(&mut self, staged: &Staged<'_>) -> Result<(), StartError> {
        self.start_inner(staged, false)
    }
    /// Request the source RTL8822C hardware-feature report before booting this
    /// exact firmware. Prior complete HCI/beacon/FIFO setup is still required.
    /// The mailbox is read back as 0xfd before download, so an old report does
    /// not satisfy this request. Raw I/O remains inaccessible until the report
    /// has been consumed; no other reset/IRQ/mailbox worker may run meanwhile.
    pub fn start_with_hardware_features(&mut self, staged: &Staged<'_>) -> Result<(), StartError> {
        self.start_inner(staged, true)
    }
    /// Consume the one actual report produced after this object's request and
    /// successful firmware boot. This is capability data, not PHY readiness.
    /// The source report helper is independent of OTP reads; Stela consumes it
    /// immediately after boot to keep the fresh mailbox exclusively owned.
    pub fn hardware_features(&mut self) -> Result<super::features::Report, Error> {
        if self.state != State::FirmwareReady || !self.feature_requested {
            return Err(Error::InvalidState);
        }
        // Mark before any fallible I/O/unwind. No repeat, even after partial ACK.
        self.state = State::Quarantined;
        self.feature_requested = false;
        match super::features::read(&mut self.io) {
            Ok(report) => {
                self.state = State::FirmwareReady;
                Ok(report)
            }
            Err(error) => {
                self.io.quarantine();
                Err(error)
            }
        }
    }
    fn start_inner(
        &mut self,
        staged: &Staged<'_>,
        request_features: bool,
    ) -> Result<(), StartError> {
        if self.state != State::Idle {
            return Err(Error::InvalidState.into());
        }
        let profile = self.io.profile();
        if staged.profile.chip() != Chip::Rtl8822C || staged.profile != profile {
            return Err(Error::WrongChip.into());
        }
        // Staged fields are diagnostic and mutable, whereas Image retains
        // the immutable Provider binding. Revalidate both before touching I/O.
        let hardware = profile.hardware_key();
        let revision = profile.revision_key();
        if staged.image.name() != profile.firmware_name()
            || staged.image.target()
                != (crate::firmware::Target {
                    driver: "realtek-wifi",
                    hardware: &hardware,
                    revision: &revision,
                    board: None,
                })
        {
            return Err(Error::WrongFirmwareTarget.into());
        }
        // Reparse the exact provider bytes; public diagnostic layouts cannot
        // be substituted to upload a different set of addresses or payloads.
        let image = Rtw88::parse(staged.image.bytes()).map_err(StartError::Format)?;
        // Set before the first possible mutation, including panicking adapters.
        self.state = State::Quarantined;
        let result = (|| {
            if request_features {
                super::features::request(&mut self.io)?;
                self.feature_requested = true;
            }
            self.download(&image)
        })();
        match result {
            Ok(()) => {
                self.state = State::FirmwareReady;
                Ok(())
            }
            Err(error) => {
                // Donor failure cleanup is best effort, never a reset proof.
                let _ = self.modify8(MCU, 1, 0);
                let _ = self.modify8(3, 0, 4);
                self.io.quarantine();
                Err(error.into())
            }
        }
    }
    fn modify8(&mut self, register: u32, clear: u8, set: u8) -> Result<(), Error> {
        let value = self.io.read8(register)?;
        self.io.write8(register, (value & !clear) | set)
    }
    fn poll(&mut self, register: u32, mask: u32, target: u32) -> Result<(), Error> {
        for _ in 0..MAX_POLLS {
            let value = self.io.read32(register)?;
            // Removed/unmapped devices must not satisfy all-set ready masks.
            if value == u32::MAX {
                return Err(Error::Register);
            }
            if value & mask == target {
                return Ok(());
            }
            self.io.delay_us(10);
        }
        Err(Error::Timeout { register, mask })
    }
    fn cpu(&mut self, enabled: bool) -> Result<(), Error> {
        if enabled {
            self.modify8(0x1d, 0, 1)?;
            self.modify8(3, 0, 4)
        } else {
            self.modify8(3, 4, 0)?;
            self.modify8(0x1d, 1, 0)
        }
    }
    fn download(&mut self, image: &Rtw88<'_>) -> Result<(), Error> {
        self.poll(LTE_CTRL, 1 << 29, 1 << 29)?;
        self.io.write32(LTE_CTRL, 0x800f_0038)?;
        let lte_backup = self.io.read32(LTE_READ)?;
        self.cpu(false)?;
        let pq = self.io.read8(0x10d)?;
        self.io.write8(0x10d, 3 << 6)?;
        let cr = self.io.read8(0x100)?;
        self.io.write8(0x100, 5)?;
        self.io.write32(0x1330, 1 << 31)?;
        let pages = self.io.read16(0x230)?;
        let rqpn = self.io.read32(0x22c)? | (1 << 31);
        self.io.write16(0x230, 0x200)?;
        self.io.write32(0x22c, rqpn)?;
        let beacon = self.io.read8(BEACON_CTRL)?;
        self.io.write8(BEACON_CTRL, (beacon & !8) | 16)?;
        self.modify8(0x1082, 1, 0)?;
        self.modify8(9, 64, 0)?;
        self.modify8(0x1082, 0, 1)?;
        self.modify8(9, 0, 64)?;
        let control = (self.io.read16(MCU)? & 0x3800) | 1;
        self.io.write16(MCU, control)?;
        for section in &image.sections {
            self.region(section.download_address, section.data)?;
        }
        // Exact donor six-register restore order and access widths. H2CQ_CSR
        // intentionally restores FULL, not an earlier register observation.
        self.io.write8(0x10d, pq)?;
        self.io.write8(0x100, cr)?;
        self.io.write32(0x1330, 1 << 31)?;
        self.io.write16(0x230, pages)?;
        self.io.write32(0x22c, rqpn)?;
        self.io.write8(BEACON_CTRL, beacon)?;
        self.io.write32(0x210, 4)?;
        let control = self.io.read16(MCU)?;
        if control & 0x50 != 0x50 {
            return Err(Error::DownloadChecksums);
        }
        self.io.write16(MCU, (control | 0x4000) & !1)?;
        self.cpu(true)?;
        self.poll(LTE_CTRL, 1 << 29, 1 << 29)?;
        self.io.write32(LTE_WRITE, lte_backup)?;
        self.io.write32(LTE_CTRL, 0xc00f_0038)?;
        match self.poll(MCU, FW_READY_MASK, FW_READY) {
            Ok(()) => Ok(()),
            Err(Error::Timeout { .. }) => {
                let debug = self.io.read32(0x10fc)?;
                if debug & 0xffff_ff00 == 0xfaaa_aa00 {
                    Err(Error::InvalidFirmwareKey)
                } else {
                    Err(Error::FirmwareNotReady { debug })
                }
            }
            Err(error) => Err(error),
        }
    }
    fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error> {
        let beacon = self.io.read8(BEACON_CTRL)?;
        self.io.write16(FIFO_PAGE, BCN_VALID)?;
        let cr = self.io.read8(CR_HIGH)?;
        self.io.write8(CR_HIGH, cr | 1)?;
        self.io.write8(BEACON_CTRL, (beacon & !8) | 16)?;
        let txq = self.io.read8(TXQ_CTRL)?;
        self.io.write8(TXQ_CTRL, txq & !64)?;
        let result = self.io.submit_beacon(data).and_then(|()| {
            self.poll(FIFO_PAGE, u32::from(BCN_VALID), u32::from(BCN_VALID))?;
            // SAFETY: cleared actual BCN_VALID before this exact payload,
            // then observed its new hardware event under exclusive I/O.
            unsafe { self.io.beacon_consumed() }
        });
        // Restore even for queue/valid-bit failure. An error in restoration is
        // itself uncertain; outer start quarantines all remaining resources.
        self.io.write16(FIFO_PAGE, self.boundary | BCN_VALID)?;
        self.io.write8(BEACON_CTRL, beacon)?;
        self.io.write8(TXQ_CTRL, txq)?;
        self.io.write8(CR_HIGH, cr)?;
        result
    }
    fn region(&mut self, destination: u32, data: &[u8]) -> Result<(), Error> {
        let control = self.io.read32(DDMA_CTRL)?;
        self.io.write32(DDMA_CTRL, control | CHECKSUM_RESET)?;
        for (index, chunk) in data.chunks(CHUNK).enumerate() {
            self.reserved_page(chunk)?;
            self.poll(DDMA_CTRL, OWN, 0)?;
            self.io.write32(DDMA_SOURCE, TX_BUFFER_PAYLOAD)?;
            self.io
                .write32(DDMA_DEST, destination + (index * CHUNK) as u32)?;
            let mut control = OWN | CHECKSUM_ENABLE | chunk.len() as u32;
            if index != 0 {
                control |= CHECKSUM_CONTINUE;
            }
            self.io.write32(DDMA_CTRL, control)?;
            self.poll(DDMA_CTRL, OWN, 0)?;
        }
        let firmware = self.io.read8(MCU)?;
        let control = self.io.read32(DDMA_CTRL)?;
        // Donor classifies EMEM with IMEM, by address rather than header kind.
        let (download_ok, checksum_ok) = if destination < IMEM_BOUNDARY {
            (8, 16)
        } else {
            (32, 64)
        };
        if control & CHECKSUM_BAD != 0 {
            self.io
                .write8(MCU, (firmware | download_ok) & !checksum_ok)?;
            return Err(Error::Checksum { destination });
        }
        self.io.write8(MCU, firmware | download_ok | checksum_ok)
    }
}
impl<I: Io> Drop for Download<I> {
    fn drop(&mut self) {
        if self.state == State::Quarantined {
            self.io.quarantine();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::firmware::{Catalog, Provenance, Resource, Target};
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::RefCell;
    use sha2::{Digest, Sha256};

    struct Model {
        profile: Profile,
        registers: Vec<u8>,
        trace: Vec<u8>,
        submitted: Vec<Vec<u8>>,
        operations: usize,
        fail_at: Option<usize>,
        stuck_ddma: bool,
        no_beacon: bool,
        bad_checksum: bool,
        no_ready: bool,
        all_ones: Option<u32>,
        quarantined: usize,
        feature_reply: Option<[u8; 13]>,
        ignore_feature_request: bool,
        ignore_feature_ack: bool,
    }
    impl Model {
        fn new() -> Self {
            let mut m = Self {
                profile: profile(),
                registers: (0..0x170c).map(|i| (i * 37 + 11) as u8).collect(),
                trace: Vec::new(),
                submitted: Vec::new(),
                operations: 0,
                fail_at: None,
                stuck_ddma: false,
                no_beacon: false,
                bad_checksum: false,
                no_ready: false,
                all_ones: None,
                quarantined: 0,
                feature_reply: None,
                ignore_feature_request: false,
                ignore_feature_ack: false,
            };
            m.set(0xf0, 4, m.profile.observed().sys_cfg1);
            m.set(MCU, 2, 0x35a5);
            m.set(DDMA_CTRL, 4, 0);
            m.set(LTE_CTRL, 4, 1 << 29);
            m.set(LTE_READ, 4, 0x1234_abcd);
            m
        }
        fn get(&self, r: u32, width: usize) -> u32 {
            let mut b = [0; 4];
            b[..width].copy_from_slice(&self.registers[r as usize..r as usize + width]);
            u32::from_le_bytes(b)
        }
        fn set(&mut self, r: u32, width: usize, value: u32) {
            self.registers[r as usize..r as usize + width]
                .copy_from_slice(&value.to_le_bytes()[..width]);
        }
        fn operation(&mut self) -> Result<(), Error> {
            let at = self.operations;
            self.operations += 1;
            if self.fail_at == Some(at) {
                Err(Error::Register)
            } else {
                Ok(())
            }
        }
        fn record(&mut self, tag: u32, register: u32, value: u32) {
            for word in [tag, register, value] {
                self.trace.extend_from_slice(&word.to_le_bytes());
            }
        }
        fn read(&mut self, r: u32, width: usize) -> Result<u32, Error> {
            self.operation()?;
            let value = if self.all_ones == Some(r) {
                u32::MAX
            } else {
                self.get(r, width)
            };
            self.record(width as u32, r, value);
            Ok(value)
        }
        fn write(&mut self, r: u32, width: usize, value: u32) -> Result<(), Error> {
            self.operation()?;
            self.record(4 + width as u32, r, value);
            if r == 0x1a0
                && ((value == 0xfd && self.ignore_feature_request)
                    || (value == 0 && self.ignore_feature_ack))
            {
                return Ok(());
            }
            let mut stored = value;
            if r == DDMA_CTRL && width == 4 {
                if !self.stuck_ddma {
                    stored &= !OWN;
                }
                if self.bad_checksum && value & OWN != 0 {
                    stored |= CHECKSUM_BAD;
                }
            }
            if r == FIFO_PAGE && width == 2 {
                stored &= !u32::from(BCN_VALID);
            }
            if r == LTE_CTRL && width == 4 {
                stored = 1 << 29;
            }
            self.set(r, width, stored);
            if r == 3 && value & 4 != 0 && !self.no_ready && self.get(MCU, 2) & 0x4050 == 0x4050 {
                self.set(MCU, 2, self.get(MCU, 2) | 0x8000);
                if self.get(0x1a0, 1) == 0xfd
                    && let Some(reply) = self.feature_reply
                {
                    self.set(0x1a0, 1, 0x19);
                    self.registers[0x1a2..0x1af].copy_from_slice(&reply);
                }
            }
            Ok(())
        }
    }
    #[derive(Clone)]
    struct ModelIo(Rc<RefCell<Model>>);
    fn profile() -> Profile {
        Profile::select(super::super::identity::Observed {
            vendor: 0x10ec,
            device: 0xc822,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            class: [2, 0x80, 0],
            sys_cfg1: 0x1000,
        })
        .unwrap()
    }
    // SAFETY: deterministic virtual requester for unit tests, no real DMA.
    // Every read/store is recorded; readiness derives from modeled events.
    unsafe impl Io for ModelIo {
        fn profile(&self) -> Profile {
            self.0.borrow().profile
        }
        fn read8(&mut self, r: u32) -> Result<u8, Error> {
            self.0.borrow_mut().read(r, 1).map(|v| v as u8)
        }
        fn read16(&mut self, r: u32) -> Result<u16, Error> {
            self.0.borrow_mut().read(r, 2).map(|v| v as u16)
        }
        fn read32(&mut self, r: u32) -> Result<u32, Error> {
            self.0.borrow_mut().read(r, 4)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), Error> {
            self.0.borrow_mut().write(r, 1, v.into())
        }
        fn write16(&mut self, r: u32, v: u16) -> Result<(), Error> {
            self.0.borrow_mut().write(r, 2, v.into())
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), Error> {
            self.0.borrow_mut().write(r, 4, v)
        }
        fn delay_us(&mut self, us: u64) {
            self.0.borrow_mut().record(9, 0, us as u32);
        }
        fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
            let mut m = self.0.borrow_mut();
            m.operation()?;
            m.record(10, 0, data.len() as u32);
            m.trace.extend_from_slice(data);
            m.submitted.push(data.to_vec());
            if !m.no_beacon {
                let value = m.get(FIFO_PAGE, 2) | u32::from(BCN_VALID);
                m.set(FIFO_PAGE, 2, value);
            }
            Ok(())
        }
        fn quarantine(&mut self) {
            self.0.borrow_mut().quarantined += 1;
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    fn catalog(bytes: Vec<u8>) -> Catalog {
        let p = profile();
        Catalog::from_handoff(vec![Resource {
            name: p.firmware_name(),
            target: Target {
                driver: "realtek-wifi",
                hardware: &p.hardware_key(),
                revision: &p.revision_key(),
                board: None,
            },
            provenance: Provenance {
                source: "synthetic",
                revision: "1",
                member: p.firmware_name(),
                license: "MIT",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        }])
        .unwrap()
    }
    fn setup() -> (Rc<RefCell<Model>>, Download<ModelIo>) {
        let m = Rc::new(RefCell::new(Model::new()));
        let d = Download::new(ModelIo(m.clone()), 0x700).unwrap();
        (m, d)
    }
    #[test]
    fn feature_request_is_fresh_and_report_stays_bound_to_same_download() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let staged = profile().stage(&c).unwrap();
        let (model, mut download) = setup();
        let raw = [
            0x91, 0x2f, 0x11, 0x3a, 0x52, 0x18, 0xef, 0xaa, 0xff, 1, 2, 3, 4,
        ];
        model.borrow_mut().feature_reply = Some(raw);
        model.borrow_mut().set(0x1a0, 1, 0x19); // Stale prior-boot ID.
        download.start_with_hardware_features(&staged).unwrap();
        assert!(matches!(
            download.after_firmware_ready(),
            Err(Error::InvalidState)
        ));
        let report = download.hardware_features().unwrap();
        assert_eq!(report.profile(), profile());
        assert_eq!(report.raw(), &raw);
        assert_eq!(
            report.capabilities(),
            super::super::features::decode(profile().observed().sys_cfg1, &raw)
        );
        assert_eq!(model.borrow().get(0x1a0, 1), 0);
        assert!(download.after_firmware_ready().is_ok());
        assert!(matches!(
            download.hardware_features(),
            Err(Error::InvalidState)
        ));
        assert_eq!(model.borrow().quarantined, 0);
        let trace = &model.borrow().trace;
        assert_eq!(
            &trace[..36],
            &[4u32, 0xf0, 0x1000, 5, 0x1a0, 0xfd, 1, 0x1a0, 0xfd]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn feature_exchange_faults_never_reuse_stale_or_partial_report() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let staged = profile().stage(&c).unwrap();
        let (good, mut d) = setup();
        good.borrow_mut().feature_reply = Some([0xff; 13]);
        d.start_with_hardware_features(&staged).unwrap();
        d.hardware_features().unwrap(); // All-ones payload is raw data, not a removal probe.
        let operations = good.borrow().operations;
        for at in 0..operations {
            let (m, mut d) = setup();
            m.borrow_mut().feature_reply = Some([0x55; 13]);
            m.borrow_mut().fail_at = Some(at);
            let failed =
                d.start_with_hardware_features(&staged).is_err() || d.hardware_features().is_err();
            assert!(failed, "operation {at}");
            assert_eq!(d.state(), State::Quarantined, "operation {at}");
            assert_eq!(m.borrow().quarantined, 1);
            assert!(matches!(d.after_firmware_ready(), Err(Error::InvalidState)));
            assert!(matches!(d.hardware_features(), Err(Error::InvalidState)));
            drop(d);
            assert_eq!(m.borrow().quarantined, 2);
        }
        for mode in 0..8 {
            let (m, mut d) = setup();
            m.borrow_mut().set(0x1a0, 1, 0x19);
            m.borrow_mut().feature_reply = Some([0; 13]);
            match mode {
                0 => m.borrow_mut().ignore_feature_request = true,
                1 => m.borrow_mut().set(0xf0, 4, u32::MAX),
                2 => m.borrow_mut().feature_reply = None,
                _ => (),
            }
            if mode < 2 {
                assert!(d.start_with_hardware_features(&staged).is_err());
                assert!(m.borrow().submitted.is_empty());
            } else {
                d.start_with_hardware_features(&staged).unwrap();
                match mode {
                    3 => m.borrow_mut().set(0xf0, 4, 0x2000),
                    4 => m.borrow_mut().set(MCU, 2, 0xffff),
                    5 => m.borrow_mut().set(0x1a0, 1, 0xff),
                    6 => m.borrow_mut().ignore_feature_ack = true,
                    7 => m.borrow_mut().set(MCU, 2, 0),
                    _ => (),
                }
                assert!(d.hardware_features().is_err(), "mode {mode}");
            }
            assert_eq!(d.state(), State::Quarantined);
            assert_eq!(m.borrow().quarantined, 1);
        }
    }
    #[test]
    fn unrequested_features_and_rebound_image_do_not_touch_hardware() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let mut staged = profile().stage(&c).unwrap();
        let (m, mut d) = setup();
        assert!(matches!(d.hardware_features(), Err(Error::InvalidState)));
        assert_eq!(m.borrow().operations, 0);
        d.start(&staged).unwrap();
        let before = m.borrow().operations;
        assert!(matches!(d.hardware_features(), Err(Error::InvalidState)));
        assert_eq!(m.borrow().operations, before);
        let mut actual = profile().observed();
        actual.subsystem_device ^= 1;
        staged.profile = Profile::select(actual).unwrap();
        let model = Rc::new(RefCell::new(Model::new()));
        model.borrow_mut().profile = staged.profile;
        let mut d = Download::new(ModelIo(model.clone()), 0x700).unwrap();
        assert!(matches!(
            d.start_with_hardware_features(&staged),
            Err(StartError::Hardware(Error::WrongFirmwareTarget))
        ));
        assert_eq!(d.state(), State::Idle);
        assert_eq!(model.borrow().operations, 0);
    }
    #[test]
    fn real_ready_requires_all_transfers_and_source_ordered_register_restoration() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let staged = profile().stage(&c).unwrap();
        let (model, mut download) = setup();
        assert!(matches!(
            download.after_firmware_ready(),
            Err(Error::InvalidState)
        ));
        let before = model.borrow().registers.clone();
        download.start(&staged).unwrap();
        assert_eq!(download.state(), State::FirmwareReady);
        assert!(download.after_firmware_ready().is_ok());
        let m = model.borrow();
        assert_eq!(m.submitted.concat(), staged.image.bytes()[64..]);
        for (r, width) in [
            (0x10d, 1),
            (0x100, 1),
            (0x230, 2),
            (BEACON_CTRL, 1),
            (CR_HIGH, 1),
            (TXQ_CTRL, 1),
        ] {
            assert_eq!(
                &m.registers[r as usize..r as usize + width],
                &before[r as usize..r as usize + width]
            );
        }
        assert_eq!(m.get(0x1330, 4), 1 << 31);
        assert_eq!(
            m.get(0x22c, 4),
            u32::from_le_bytes(before[0x22c..0x230].try_into().unwrap()) | 1 << 31
        );
        assert_eq!(m.get(MCU, 2) & FW_READY_MASK, FW_READY);
        assert_eq!(m.quarantined, 0);
        drop(m);
        assert!(matches!(
            download.start(&staged),
            Err(StartError::Hardware(Error::InvalidState))
        ));
    }
    #[test]
    fn every_uncertain_operation_is_terminal_and_keeps_submitted_memory_quarantined() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let staged = profile().stage(&c).unwrap();
        let (reference, mut ok) = setup();
        ok.start(&staged).unwrap();
        let operations = reference.borrow().operations;
        for at in 0..operations {
            let (m, mut d) = setup();
            m.borrow_mut().fail_at = Some(at);
            assert!(d.start(&staged).is_err(), "operation {at}");
            assert_eq!(d.state(), State::Quarantined, "operation {at}");
            assert_eq!(m.borrow().quarantined, 1);
            let submitted = m.borrow().submitted.clone();
            assert!(matches!(
                d.start(&staged),
                Err(StartError::Hardware(Error::InvalidState))
            ));
            drop(d);
            assert_eq!(m.borrow().quarantined, 2);
            assert_eq!(m.borrow().submitted, submitted);
        }
    }
    #[test]
    fn own_valid_checksum_ready_and_removed_device_failures_are_distinct_and_bounded() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let staged = profile().stage(&c).unwrap();
        for mode in 0..7 {
            let (m, mut d) = setup();
            match mode {
                0 => m.borrow_mut().stuck_ddma = true,
                1 => m.borrow_mut().no_beacon = true,
                2 => m.borrow_mut().bad_checksum = true,
                3 | 4 => {
                    m.borrow_mut().no_ready = true;
                    m.borrow_mut()
                        .set(0x10fc, 4, if mode == 4 { 0xfaaa_aa00 } else { 0x1234 });
                }
                5 => m.borrow_mut().all_ones = Some(LTE_CTRL),
                _ => m.borrow_mut().all_ones = Some(DDMA_CTRL),
            }
            let Err(StartError::Hardware(error)) = d.start(&staged) else {
                panic!("mode {mode}");
            };
            assert_eq!(
                error,
                match mode {
                    0 => Error::Timeout {
                        register: DDMA_CTRL,
                        mask: OWN
                    },
                    1 => Error::Timeout {
                        register: FIFO_PAGE,
                        mask: BCN_VALID.into()
                    },
                    2 => Error::Checksum {
                        destination: 0x200000
                    },
                    3 => Error::FirmwareNotReady { debug: 0x1234 },
                    4 => Error::InvalidFirmwareKey,
                    _ => Error::Register,
                }
            );
            assert!(m.borrow().operations < 1300);
            assert_eq!(d.state(), State::Quarantined);
            assert_eq!(m.borrow().quarantined, 1);
        }
    }
    #[test]
    fn a_different_exact_provider_target_cannot_be_uploaded_to_this_requester() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        let mut staged = profile().stage(&c).unwrap();
        let mut changed = profile().observed();
        changed.subsystem_device ^= 1;
        staged.profile = Profile::select(changed).unwrap();
        let (m, mut d) = setup();
        assert!(matches!(
            d.start(&staged),
            Err(StartError::Hardware(Error::WrongChip))
        ));
        assert_eq!(d.state(), State::Idle);
        assert_eq!(m.borrow().operations, 0);
        assert_eq!(m.borrow().quarantined, 0);
        assert!(matches!(
            Download::new(ModelIo(m), 0x800),
            Err(Error::InvalidBoundary)
        ));
    }
    #[test]
    fn forged_diagnostic_profile_cannot_rebind_another_requesters_provider_image() {
        let c = catalog(super::super::firmware::tests::legacy_fixture());
        for field in 0..5 {
            let mut staged = profile().stage(&c).unwrap();
            let mut actual = profile().observed();
            match field {
                0 => actual.device = 0xc82f,
                1 => actual.subsystem_vendor ^= 1,
                2 => actual.subsystem_device ^= 1,
                3 => actual.pci_revision ^= 1,
                _ => actual.sys_cfg1 ^= 1,
            }
            let actual = Profile::select(actual).unwrap();
            staged.profile = actual;
            let (m, mut d) = setup();
            m.borrow_mut().profile = actual;
            assert!(matches!(
                d.start(&staged),
                Err(StartError::Hardware(Error::WrongFirmwareTarget))
            ));
            assert_eq!(d.state(), State::Idle);
            assert_eq!(m.borrow().operations, 0);
            assert!(m.borrow().submitted.is_empty());
            assert_eq!(m.borrow().quarantined, 0);
        }
    }
    #[test]
    fn native_register_adapter_bounds_alignment_and_quarantine_prevent_invalid_access() {
        use core::sync::atomic::AtomicU32;
        struct NoDma;
        // SAFETY: this fixture owns no DMA, and deliberately refuses every
        // submission. It only tests local volatile register window validation.
        unsafe impl BeaconQueue for NoDma {
            fn submit(&mut self, _: &[u8]) -> Result<(), Error> {
                Err(Error::Queue)
            }
            fn quarantine(&mut self) {}
            unsafe fn consumed(&mut self) -> Result<(), Error> {
                Err(Error::Queue)
            }
        }
        let memory: Arc<Vec<AtomicU32>> =
            Arc::new((0..0x170c / 4).map(|_| AtomicU32::new(0)).collect());
        let owner = Arc::downgrade(&memory);
        let address = memory[0].as_ptr() as u64;
        // A local interior-mutable virtual register window, not a fabricated
        // PCI claim passed through NativeIo's public unsafe constructor.
        // There are no concurrent accesses, including atomic operations.
        let mut io = NativeIo {
            registers: unsafe { Mmio::new(address) },
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            profile: profile(),
            bytes: 0x170c,
            owned: Some((NoDma, memory)),
        };
        io.write32(0x1708, 0x1234_abcd).unwrap();
        assert_eq!(io.read32(0x1708), Ok(0x1234_abcd));
        assert_eq!(io.read32(0x170c), Err(Error::Register));
        assert_eq!(io.read32(u32::MAX), Err(Error::Register));
        assert_eq!(io.read16(0x170b), Err(Error::Register));
        assert_eq!(io.write32(1, 0), Err(Error::Register));
        io.quarantine();
        assert!(matches!(io.beacon_queue(), Err(Error::InvalidState)));
        assert_eq!(io.read32(0), Err(Error::Register));
        assert_eq!(io.submit_beacon(&[0]), Err(Error::InvalidState));
        drop(io);
        assert!(
            owner.upgrade().is_some(),
            "uncertain BAR owner must be retained"
        );
    }
    #[test]
    #[ignore = "requires pinned actual RTL8822C image and C transport oracle"]
    fn actual_firmware_download_register_and_packet_trace_matches_unchanged_c() {
        let root = std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap();
        let c = catalog(
            std::fs::read(std::path::Path::new(&root).join("rtw88/rtw8822c_fw.bin")).unwrap(),
        );
        let staged = profile().stage(&c).unwrap();
        let (m, mut d) = setup();
        d.start(&staged).unwrap();
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSPORT_ORACLE").unwrap()).unwrap();
        assert_eq!(m.borrow().trace, trace);
        assert_eq!(m.borrow().submitted.concat(), staged.image.bytes()[64..]);
        assert_eq!(d.state(), State::FirmwareReady);
        assert_eq!(m.borrow().submitted.len(), 51);
    }
    #[test]
    #[ignore = "requires actual RTL8822C image and unchanged C transport oracle"]
    fn actual_download_uses_native_pinned_beacon_dma_with_each_new_completion() {
        use super::super::beacon::tests::Harness;
        struct Combined {
            control: ModelIo,
            queue: Harness,
        }
        // SAFETY: both synchronous hardware models are serialized. A source
        // beacon-valid event is produced only after the real native queue has
        // published actual model IOVAs and the modeled device copied bytes.
        unsafe impl Io for Combined {
            fn profile(&self) -> Profile {
                self.control.profile()
            }
            fn read8(&mut self, r: u32) -> Result<u8, Error> {
                self.control.read8(r)
            }
            fn read16(&mut self, r: u32) -> Result<u16, Error> {
                self.control.read16(r)
            }
            fn read32(&mut self, r: u32) -> Result<u32, Error> {
                self.control.read32(r)
            }
            fn write8(&mut self, r: u32, v: u8) -> Result<(), Error> {
                self.control.write8(r, v)
            }
            fn write16(&mut self, r: u32, v: u16) -> Result<(), Error> {
                self.control.write16(r, v)
            }
            fn write32(&mut self, r: u32, v: u32) -> Result<(), Error> {
                self.control.write32(r, v)
            }
            fn delay_us(&mut self, us: u64) {
                self.control.delay_us(us);
            }
            fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
                self.queue.submit(data)?;
                self.control.submit_beacon(data)
            }
            unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
                unsafe { self.queue.consumed() }
            }
            fn quarantine(&mut self) {
                self.queue.quarantine();
                self.control.quarantine();
            }
        }
        let root = std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap();
        let c = catalog(
            std::fs::read(std::path::Path::new(&root).join("rtw88/rtw8822c_fw.bin")).unwrap(),
        );
        let staged = profile().stage(&c).unwrap();
        let model = Rc::new(RefCell::new(Model::new()));
        let mut d = Download::new(
            Combined {
                control: ModelIo(model.clone()),
                queue: Harness::new(),
            },
            0x700,
        )
        .unwrap();
        d.start(&staged).unwrap();
        let packets = d.io.queue.packets();
        assert_eq!(packets.len(), 51);
        assert_eq!(
            packets
                .iter()
                .flat_map(|p| p[48..].iter().copied())
                .collect::<Vec<_>>(),
            staged.image.bytes()[64..]
        );
        assert!(!d.io.queue.pending());
        assert_eq!(
            d.io.queue.mappings(),
            2,
            "MCU ready cannot unmap active queue base"
        );
        let oracle =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSPORT_ORACLE").unwrap()).unwrap();
        assert_eq!(model.borrow().trace, oracle);
        // SAFETY: synchronous modeled device and submission workers stopped,
        // independently of the MCU-ready state, before canonical unmaps.
        unsafe {
            d.io.queue.stop();
        }
        assert_eq!(d.io.queue.mappings(), 0);
    }
}
