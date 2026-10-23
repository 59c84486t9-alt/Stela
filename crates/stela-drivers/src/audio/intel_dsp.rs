// SPDX-License-Identifier: GPL-2.0-only
//! Intel cAVS 2.5 SOF IPC3 hardware backend.
//!
//! Linux SOF at a804c5742bff224d4cb4d25dd383554d598be32b supplies the
//! register, ROM, mailbox and DMA recipes; see audio/THIRD_PARTY.md. Firmware
//! remains an original external catalog image. SST, AVS, IPC4 and ACE are
//! different protocols and are explicitly outside this profile.
//! Copyright(c) 2018, 2020 Intel Corporation
use alloc::sync::Arc;

use crate::bus::{
    dma::{
        mapping::{DmaDomain, DmaError},
        memory::{MemoryError, PageSource},
    },
    i2c::Timer,
};
use crate::firmware::Image;

mod dma;
mod ipc;
pub mod pci;
mod registers;
pub mod topology;
use dma::Stream;
use registers::*;
pub use registers::{Bar, Registers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
}
impl Identity {
    fn supported(self) -> bool {
        self.vendor == 0x8086
            && matches!(
                self.device,
                0xa0c8 | 0x43c8 | 0x7ad0 | 0x51c8 | 0x51c9 | 0x51cc | 0x51cd | 0x54c8
            )
    }
    fn hardware(self) -> &'static str {
        match self.device {
            0xa0c8 => "8086:a0c8",
            0x43c8 => "8086:43c8",
            0x7ad0 => "8086:7ad0",
            0x51c8 => "8086:51c8",
            0x51c9 => "8086:51c9",
            0x51cc => "8086:51cc",
            0x51cd => "8086:51cd",
            0x54c8 => "8086:54c8",
            _ => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Claimed,
    Ready,
    Firmware,
    Prepared,
    Running,
    Stopped,
    Faulted,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    LinkReset,
    CorePower,
    CoreReset,
    Rom,
    Firmware,
    Ipc,
    StreamReset,
    StreamRun,
    CoreOff,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedController,
    Authority,
    InvalidBar,
    InvalidConfiguration,
    Register(Bar, usize),
    Rejected(Bar, usize),
    Timeout(Phase),
    Busy,
    State,
    Capability,
    FirmwareImage,
    FirmwarePanic(u32),
    FirmwareAbi(u32),
    Mailbox,
    IpcReply,
    IpcError(i32),
    Topology,
    UnsupportedTopology,
    StreamFault(u8),
    Buffer,
    Memory(MemoryError),
    Dma(DmaError),
    NeedsReset,
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<DmaError> for Error {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Identity/platform DMA ceiling, intersected with HDA GCAP.
    pub dma_address_bits: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareReport {
    pub sha256: [u8; 32],
    pub abi: u32,
    pub major: u16,
    pub minor: u16,
    pub micro: u16,
    pub build: u16,
}
#[derive(Clone, Copy)]
struct Mailboxes {
    host: usize,
    host_bytes: usize,
    dsp: usize,
    dsp_bytes: usize,
}

/// Polled held-D0 owner. Any failed operation after publication poisons further
/// submission; shutdown remains available and retains every uncertain resource.
pub struct Controller<R, T> {
    registers: R,
    timer: T,
    identity: Identity,
    config: Config,
    state: State,
    input_streams: u8,
    output_streams: u8,
    pp: usize,
    spib: usize,
    limit: u64,
    boot: Option<Stream>,
    iccmax: Option<Stream>,
    pcm: Option<Stream>,
    mailboxes: Option<Mailboxes>,
    report: Option<FirmwareReport>,
    graph: Option<topology::Installed>,
    saved_em2: Option<u32>,
    saved_guard: Option<u8>,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub fn claim(mut registers: R, timer: T, config: Config) -> Result<Self, (Error, R, T)> {
        let result = (|| {
            let identity = registers.identity()?;
            if !identity.supported() {
                return Err(Error::UnsupportedController);
            }
            if !(32..=64).contains(&config.dma_address_bits)
                || registers.bytes(Bar::Hda) < 0x2000
                || registers.bytes(Bar::Dsp) < 0x100000
            {
                return Err(Error::InvalidConfiguration);
            }
            Ok(identity)
        })();
        let identity = match result {
            Ok(id) => id,
            Err(error) => return Err((error, registers, timer)),
        };
        Ok(Self {
            registers,
            timer,
            identity,
            config,
            state: State::Claimed,
            input_streams: 0,
            output_streams: 0,
            pp: 0,
            spib: 0,
            limit: 0,
            boot: None,
            iccmax: None,
            pcm: None,
            mailboxes: None,
            report: None,
            graph: None,
            saved_em2: None,
            saved_guard: None,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn firmware_report(&self) -> Option<FirmwareReport> {
        self.report
    }
    fn authority(&mut self) -> Result<(), Error> {
        if self.registers.identity()? != self.identity {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn guard(&mut self, states: &[State]) -> Result<(), Error> {
        if !states.contains(&self.state) {
            return Err(if self.state == State::Faulted {
                Error::NeedsReset
            } else {
                Error::State
            });
        }
        let result = self.authority();
        self.finish(result)
    }
    fn finish<V>(&mut self, result: Result<V, Error>) -> Result<V, Error> {
        if result.is_err() {
            self.state = State::Faulted;
        }
        result
    }
    fn read(&mut self, bar: Bar, offset: usize) -> Result<u32, Error> {
        self.registers.read32(bar, offset)
    }
    fn write(&mut self, bar: Bar, offset: usize, value: u32) -> Result<(), Error> {
        self.registers.write32(bar, offset, value)
    }
    fn update(&mut self, bar: Bar, offset: usize, mask: u32, bits: u32) -> Result<(), Error> {
        let old = self.read(bar, offset)?;
        self.write(bar, offset, (old & !mask) | (bits & mask))
    }
    #[allow(clippy::too_many_arguments)] // one register phase and its pre-write deadline
    fn poll(
        &mut self,
        bar: Bar,
        offset: usize,
        mask: u32,
        expected: u32,
        start: u64,
        timeout: u64,
        phase: Phase,
    ) -> Result<u32, Error> {
        loop {
            if self.timer.now_us().wrapping_sub(start) >= timeout {
                return Err(Error::Timeout(phase));
            }
            let value = self.read(bar, offset)?;
            if self.timer.now_us().wrapping_sub(start) >= timeout {
                return Err(Error::Timeout(phase));
            }
            if value & mask == expected {
                return Ok(value);
            }
            self.timer.relax();
        }
    }
    #[allow(clippy::too_many_arguments)] // requested and observed fields differ for power
    fn transition(
        &mut self,
        bar: Bar,
        offset: usize,
        mask: u32,
        bits: u32,
        observed: u32,
        expected: u32,
        timeout: u64,
        phase: Phase,
    ) -> Result<(), Error> {
        let start = self.timer.now_us();
        self.update(bar, offset, mask, bits)?;
        self.poll(bar, offset, observed, expected, start, timeout, phase)?;
        Ok(())
    }
    fn delay(&self, micros: u64) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < micros {
            self.timer.relax();
        }
    }
    /// Full controller reset, processing and SPIB discovery. Admission requires
    /// all host streams, command rings and DSP cores actually stopped first.
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.guard(&[State::Claimed])?;
        let result = (|| {
            let gcap = self.registers.read16(Bar::Hda, GCAP)?;
            let inputs = ((gcap >> 8) & 15) as u8;
            let outputs = ((gcap >> 12) & 15) as u8;
            if inputs == 0 || outputs == 0 || inputs + outputs > 30 || gcap & 0xf8 != 0 {
                return Err(Error::Capability);
            }
            self.input_streams = inputs;
            self.output_streams = outputs;
            if self.registers.read8(Bar::Hda, CORBCTL)? & 2 != 0
                || self.registers.read8(Bar::Hda, RIRBCTL)? & 2 != 0
            {
                return Err(Error::Busy);
            }
            for index in 0..inputs + outputs {
                if self.registers.read8(Bar::Hda, stream_base(index))? & 3 != 0 {
                    return Err(Error::Busy);
                }
            }
            let cores = self.read(Bar::Dsp, ADSPCS)?;
            // Additional cores are firmware-managed on cAVS2.5. A prior running
            // firmware cannot be taken over by resetting only core0.
            if cores & 0x0f0f0000 != 0 {
                return Err(Error::Busy);
            }
            let (pp, spib) = registers::capabilities(&mut self.registers, inputs + outputs)?;
            self.pp = pp;
            self.spib = spib;
            let bits = self
                .config
                .dma_address_bits
                .min(if gcap & 1 != 0 { 64 } else { 32 });
            self.limit = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            self.write(Bar::Hda, INTCTL, 0)?;
            self.registers.misc_clock_gate(false)?;
            self.transition(Bar::Hda, GCTL, 1, 0, 1, 0, 100_000, Phase::LinkReset)?;
            self.delay(500);
            self.transition(Bar::Hda, GCTL, 1, 1, 1, 1, 100_000, Phase::LinkReset)?;
            self.delay(1000);
            self.registers.misc_clock_gate(true)?;
            let (new_pp, new_spib) =
                registers::capabilities(&mut self.registers, inputs + outputs)?;
            if (pp, spib) != (new_pp, new_spib) {
                return Err(Error::Authority);
            }
            self.update(Bar::Hda, pp + PPCTL, GPROCEN | PIE, GPROCEN)?;
            if self.read(Bar::Hda, pp + PPCTL)? & (GPROCEN | PIE) != GPROCEN {
                return Err(Error::Rejected(Bar::Hda, pp + PPCTL));
            }
            self.write(Bar::Dsp, IPCCTL, 0)?;
            self.update(Bar::Dsp, ADSPIC, 1, 0)?;
            self.saved_em2 = Some(self.read(Bar::Hda, EM2)?);
            self.registers.hold_d0()?;
            self.update(Bar::Hda, EM2, L1SEN, 0)?;
            self.saved_guard = Some(self.registers.read8(Bar::Hda, LTRP)? & 0x3f);
            self.registers.set_bus_master(true)?;
            self.state = State::Ready;
            Ok(())
        })();
        self.finish(result)
    }

    /// Upload the selected original firmware through real HDA code-loader DMA.
    /// The catalog binds exact input bytes and provenance to this PCI identity.
    /// Only IPC3, complete cold boot is accepted; no IMR shortcut is inferred.
    pub fn boot(
        &mut self,
        image: Image<'_>,
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<FirmwareReport, Error> {
        self.guard(&[State::Ready])?;
        if image.target().driver != "intel-dsp"
            || image.target().hardware != self.identity.hardware()
            || image.target().revision != "cavs2.5-ipc3"
        {
            return Err(Error::FirmwareImage);
        }
        let payload = ipc::firmware_payload(image.bytes())?;
        let mut loader = Stream::allocate(
            pages,
            domain.clone(),
            payload.len(),
            self.limit,
            self.input_streams,
            1,
            crate::audio::Direction::Playback,
        )?;
        loader.copy_to(0, payload)?;
        let iccmax = Stream::allocate(
            pages,
            domain,
            4096,
            self.limit,
            0,
            1,
            crate::audio::Direction::Capture,
        )?;
        self.boot = Some(loader);
        self.iccmax = Some(iccmax);
        let result = (|| {
            self.program_stream(true, true)?;
            // 95us in the source is intentionally truncated by the 6-bit
            // field (0x1f); preserve the remaining vendor byte.
            let guard = self.registers.read8(Bar::Hda, LTRP)?;
            self.registers
                .write8(Bar::Hda, LTRP, (guard & !0x3f) | (95 & 0x3f))?;
            self.stream_run(true, true, true)?;
            self.program_stream(true, false)?;
            self.transition(
                Bar::Dsp,
                ADSPCS,
                1 << 16,
                1 << 16,
                1 << 24,
                1 << 24,
                50_000,
                Phase::CorePower,
            )?;
            for index in 0..3 {
                self.update(Bar::Dsp, 0x10000 + index * 0x1000 + 4, 3 << 24, 3 << 24)?;
            }
            let start = self.timer.now_us();
            self.write(Bar::Dsp, IPC_REQ, BUSY | 0x01004000)?;
            self.transition(Bar::Dsp, ADSPCS, 1, 0, 1, 0, 50_000, Phase::CoreReset)?;
            self.update(Bar::Dsp, ADSPCS, 1 << 8, 0)?;
            if self.read(Bar::Dsp, ADSPCS)? & 0x01010101 != 0x01010000 {
                return Err(Error::Rejected(Bar::Dsp, ADSPCS));
            }
            self.poll(Bar::Dsp, IPC_ACK, BUSY, BUSY, start, 500_000, Phase::Rom)?;
            self.update(Bar::Dsp, IPC_ACK, BUSY, BUSY)?;
            let start = self.timer.now_us();
            self.poll(
                Bar::Dsp,
                ROM_STATUS,
                0x80ffffff,
                1,
                start,
                300_000,
                Phase::Rom,
            )?;
            // Polled transport keeps all PCI and DSP interrupt delivery masked.
            self.stream_run(true, false, true)?;
            let start = self.timer.now_us();
            self.poll(
                Bar::Dsp,
                ROM_STATUS,
                0x80ffffff,
                5,
                start,
                3_000_000,
                Phase::Firmware,
            )?;
            self.stream_run(true, false, false)?;
            self.stream_run(true, true, false)?;
            self.clear_loader_registers()?;
            let report = self.firmware_ready(image.sha256())?;
            self.state = State::Firmware;
            self.report = Some(report);
            Ok(report)
        })();
        self.finish(result)
    }
    fn clear_loader_registers(&mut self) -> Result<(), Error> {
        for index in [0, self.input_streams] {
            let base = stream_base(index);
            self.write(Bar::Hda, base + BDLPL, 0)?;
            self.write(Bar::Hda, base + BDLPU, 0)?;
            self.write(Bar::Hda, self.spib + 8 + usize::from(index) * 8, 0)?;
            self.update(Bar::Hda, self.spib + 4, 1 << index, 0)?;
            self.update(Bar::Hda, self.pp + PPCTL, 1 << index, 0)?;
        }
        if let Some(saved) = self.saved_guard {
            let current = self.registers.read8(Bar::Hda, LTRP)?;
            self.registers
                .write8(Bar::Hda, LTRP, (current & !0x3f) | saved)?;
        }
        Ok(())
    }

    /// Disable engines and core0 before actual remapper drain/unmap. Failed
    /// acknowledgements retain mappings and the native PCI/MMIO owners.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Ok(());
        }
        let authority = self.authority();
        self.finish(authority)?;
        let result = (|| {
            if self.pcm.is_some() {
                self.stream_run(false, false, false)?;
            }
            if self.boot.is_some() {
                self.stream_run(true, false, false)?;
            }
            if self.iccmax.is_some() {
                self.stream_run(true, true, false)?;
            }
            self.write(Bar::Dsp, IPCCTL, 0)?;
            self.update(Bar::Dsp, ADSPIC, 1, 0)?;
            self.transition(
                Bar::Dsp,
                ADSPCS,
                0x101,
                0x101,
                0x101,
                0x101,
                50_000,
                Phase::CoreReset,
            )?;
            self.transition(
                Bar::Dsp,
                ADSPCS,
                1 << 16,
                0,
                0x0f000000,
                0,
                50_000,
                Phase::CoreOff,
            )?;
            if self.pp != 0 {
                self.write(Bar::Hda, self.pp + PPCTL, 0)?;
                if self.read(Bar::Hda, self.pp + PPCTL)? != 0 {
                    return Err(Error::Rejected(Bar::Hda, self.pp + PPCTL));
                }
            }
            self.registers.set_bus_master(false)?;
            for stream in [&mut self.pcm, &mut self.boot, &mut self.iccmax]
                .into_iter()
                .flatten()
            {
                stream.retire()?;
            }
            self.pcm = None;
            self.boot = None;
            self.iccmax = None;
            if let Some(saved) = self.saved_em2 {
                self.update(Bar::Hda, EM2, L1SEN, saved)?;
            }
            self.mailboxes = None;
            self.graph = None;
            self.report = None;
            self.state = State::Shutdown;
            Ok(())
        })();
        self.finish(result)
    }
    pub fn into_stopped_resources(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            return Err(self);
        }
        Ok((self.registers, self.timer))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::dma::{
        mapping::{Direction as DmaDirection, DomainMapping},
        memory::{CacheAttribute, CpuMapping, PageBacking, PageGeometry, PinnedPages},
        pages::DmaPages,
    };
    use crate::firmware::{Catalog, Provenance, Provider, Requirement, Resource, Target};
    use alloc::{boxed::Box, vec, vec::Vec};
    use core::{
        cell::UnsafeCell,
        ops::Range,
        ptr::NonNull,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    #[repr(align(4096))]
    struct Ram([u8; 16384]);
    struct Backing {
        ram: Box<UnsafeCell<Ram>>,
        physical: Vec<u64>,
        drops: Arc<AtomicUsize>,
    }
    // SAFETY: isolated stable model allocation with synchronized raw DMA access.
    unsafe impl Send for Backing {}
    // SAFETY: no CPU references escape its UnsafeCell; accesses are serialized.
    unsafe impl Sync for Backing {}
    // SAFETY: real aligned RAM, immutable scattered symbolic physical labels;
    // those labels are resolved only by the model and never CPU-dereferenced.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Source {
        drops: Arc<AtomicUsize>,
        next: AtomicU64,
    }
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            PageGeometry::base_only(12)
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert!(bytes <= 16384);
            assert_eq!(alignment, 4096);
            assert_eq!(attribute, CacheAttribute::WriteBack);
            let base = self.next.fetch_add(0x100000, Ordering::Relaxed);
            PinnedPages::new(
                Box::new(Backing {
                    ram: Box::new(UnsafeCell::new(Ram([0; 16384]))),
                    physical: (0..bytes / 4096)
                        .map(|page| base + page as u64 * 0x3000)
                        .collect(),
                    drops: self.drops.clone(),
                }),
                bytes,
                alignment,
            )
        }
    }
    struct Translation {
        token: DomainMapping,
        cpu: CpuMapping,
        _pin: DmaPages,
        direction: DmaDirection,
        device_owned: bool,
    }
    struct Model {
        hda: Vec<u8>,
        dsp: Vec<u8>,
        translations: Vec<Translation>,
        next: u64,
        master: bool,
        clock_gate: bool,
        held_d0: bool,
        rom: bool,
        firmware: bool,
        capture: bool,
        cursor: usize,
        produced: usize,
        commands: Vec<u32>,
        stall_reply: bool,
        stall_stop: bool,
        fail_unmap: Option<u64>,
        fail_drain: bool,
        unmaps: usize,
        drained: usize,
        writes: Vec<(Bar, usize, u32)>,
    }
    impl Model {
        fn new() -> Self {
            let mut model = Self {
                hda: vec![0; 0x4000],
                dsp: vec![0; 0x100000],
                translations: Vec::new(),
                next: 1,
                master: false,
                clock_gate: true,
                held_d0: false,
                rom: false,
                firmware: false,
                capture: false,
                cursor: 0,
                produced: 0,
                commands: Vec::new(),
                stall_reply: false,
                stall_stop: false,
                fail_unmap: None,
                fail_drain: false,
                unmaps: 0,
                drained: 0,
                writes: Vec::new(),
            };
            model.hda[..2].copy_from_slice(&0x1101u16.to_le_bytes());
            model.hda[0x14..0x16].copy_from_slice(&0x1000u16.to_le_bytes());
            ipc::put(&mut model.hda, 0x1000, 0x10031100);
            ipc::put(&mut model.hda, 0x1100, 0x10040000);
            ipc::put(&mut model.dsp, 4, 0x101);
            model
        }
        fn bytes(&self, bar: Bar) -> &[u8] {
            match bar {
                Bar::Hda => &self.hda,
                Bar::Dsp => &self.dsp,
            }
        }
        fn bytes_mut(&mut self, bar: Bar) -> &mut [u8] {
            match bar {
                Bar::Hda => &mut self.hda,
                Bar::Dsp => &mut self.dsp,
            }
        }
        fn load(&self, bar: Bar, offset: usize) -> u32 {
            ipc::word(self.bytes(bar), offset).unwrap()
        }
        fn store(&mut self, bar: Bar, offset: usize, value: u32) {
            ipc::put(self.bytes_mut(bar), offset, value);
        }
        fn translate(&self, address: u64, bytes: usize, write: bool) -> NonNull<u8> {
            let map = self
                .translations
                .iter()
                .find(|map| {
                    address >= map.token.address
                        && address + bytes as u64 <= map.token.address + map.token.bytes as u64
                })
                .expect("actual domain IOVA");
            assert!(map.device_owned);
            if write {
                assert_eq!(map.direction, DmaDirection::FromDevice);
            } else {
                assert_eq!(map.direction, DmaDirection::ToDevice);
            }
            map.cpu
                .address((address - map.token.address) as usize, bytes)
                .unwrap()
        }
        fn stream_chunks(&self, index: u8) -> Vec<(u64, usize)> {
            let base = stream_base(index);
            let bdl = u64::from(self.load(Bar::Hda, base + BDLPL))
                | (u64::from(self.load(Bar::Hda, base + BDLPU)) << 32);
            let entries =
                u16::from_le_bytes(self.hda[base + LVI..base + LVI + 2].try_into().unwrap())
                    as usize
                    + 1;
            assert!(entries >= 2);
            let mut result = Vec::new();
            for index in 0..entries {
                let pointer = self.translate(bdl + index as u64 * 16, 16, false);
                // SAFETY: checked retained model descriptor allocation.
                let entry = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), 16) };
                let address = u64::from_le_bytes(entry[..8].try_into().unwrap());
                let bytes = ipc::word(entry, 8).unwrap() as usize;
                assert!(address.is_multiple_of(128));
                assert!(bytes > 0);
                result.push((address, bytes));
            }
            assert_eq!(
                result.iter().map(|(_, bytes)| bytes).sum::<usize>(),
                self.load(Bar::Hda, base + CBL) as usize
            );
            result
        }
        fn ready(&mut self) {
            self.firmware = true;
            self.store(Bar::Dsp, ROM_STATUS, 5);
            let mut ready = [0; 108];
            ipc::put(&mut ready, 0, 108);
            ipc::put(&mut ready, 4, 0x70000000);
            ipc::put(&mut ready, 24, 60);
            ready[28] = 2;
            ready[30] = 11;
            ipc::put(&mut ready, 64, 0x03017001);
            self.dsp[0x81000..0x81000 + 108].copy_from_slice(&ready);
            let mut windows = [0; 64];
            ipc::put(&mut windows, 0, 64);
            ipc::put(&mut windows, 4, 0x70000000);
            ipc::put(&mut windows, 8, 1);
            ipc::put(&mut windows, 12, 2);
            for (at, kind, offset) in [(16, 0, 0x3000), (40, 1, 0x4000)] {
                ipc::put(&mut windows, at, 24);
                ipc::put(&mut windows, at + 4, kind);
                ipc::put(&mut windows, at + 16, 384);
                ipc::put(&mut windows, at + 20, offset);
            }
            self.dsp[0x81000 + 108..0x81000 + 172].copy_from_slice(&windows);
            self.store(Bar::Dsp, IPC_NOTIFY, BUSY | 0x70000000);
        }
        fn write32(&mut self, bar: Bar, offset: usize, value: u32) {
            self.writes.push((bar, offset, value));
            if bar == Bar::Dsp && offset == ADSPCS {
                let requested = (value >> 16) & 15;
                self.store(bar, offset, (value & 0x00ffffff) | requested << 24);
                if self.rom && value & 0x101 == 0 {
                    self.store(Bar::Dsp, IPC_ACK, BUSY);
                    self.store(Bar::Dsp, ROM_STATUS, 1);
                }
            } else if bar == Bar::Dsp && matches!(offset, IPC_ACK | IPC_NOTIFY) {
                self.store(bar, offset, self.load(bar, offset) & !(value & BUSY));
            } else if bar == Bar::Dsp && offset == IPC_REQ {
                if value == BUSY | 0x01004000 {
                    self.rom = true;
                    self.store(bar, offset, 0);
                } else {
                    assert_eq!(value, BUSY);
                    assert!(self.firmware && self.master);
                    let cmd = self.load(Bar::Dsp, 0x83004);
                    self.commands.push(cmd);
                    if self.stall_reply {
                        self.store(bar, offset, BUSY);
                        return;
                    }
                    let size = if cmd == 0x60010000 {
                        assert_eq!(self.load(Bar::Dsp, 0x83000), 108);
                        assert_eq!(self.load(Bar::Dsp, 0x83018), 84);
                        20
                    } else {
                        12
                    };
                    if cmd == 0x60040000 || cmd == 0x60070000 {
                        self.capture = true;
                    }
                    if cmd == 0x60060000 {
                        self.capture = false;
                    }
                    let host = self.load(Bar::Dsp, 0x83008);
                    self.dsp[0x83000..0x83000 + size].fill(0);
                    self.store(Bar::Dsp, 0x83000, size as u32);
                    self.store(Bar::Dsp, 0x83004, 0x10000000);
                    if size == 20 {
                        self.store(Bar::Dsp, 0x8300c, host);
                    }
                    self.store(Bar::Dsp, IPC_REQ, 0);
                    self.store(Bar::Dsp, IPC_ACK, BUSY);
                }
            } else {
                if bar == Bar::Hda && offset == GCTL {
                    assert!(!self.clock_gate);
                }
                self.store(bar, offset, value);
            }
        }
        fn write8(&mut self, bar: Bar, offset: usize, value: u8) {
            if bar == Bar::Hda && (0x80..0xc0).contains(&offset) && (offset - 0x80) % 0x20 == 3 {
                self.hda[offset] &= !value;
                return;
            }
            if bar == Bar::Hda && matches!(offset, 0x80 | 0xa0) {
                if value & RUN == 0 && self.hda[offset] & RUN != 0 && self.stall_stop {
                    return;
                }
                self.hda[offset] = value;
                if offset == 0xa0 && value & RUN != 0 {
                    assert!(self.rom && self.held_d0 && self.master);
                    assert_ne!(self.load(Bar::Hda, 0x1004) & (1 << 1), 0);
                    let chunks = self.stream_chunks(1);
                    let mut payload = Vec::new();
                    for (address, bytes) in chunks {
                        let pointer = self.translate(address, bytes, false);
                        unsafe {
                            payload.extend_from_slice(core::slice::from_raw_parts(
                                pointer.as_ptr(),
                                bytes,
                            ));
                        }
                    }
                    assert_eq!(payload, vec![0x5a; 4096]);
                    self.ready();
                }
            } else {
                self.bytes_mut(bar)[offset] = value;
            }
        }
        fn advance(&mut self, bytes: usize) {
            assert!(self.capture && self.hda[0x80] & RUN != 0 && self.master);
            let chunks = self.stream_chunks(0);
            let ring: usize = chunks.iter().map(|(_, n)| n).sum();
            for _ in 0..bytes {
                let mut offset = self.cursor;
                let mut address = None;
                for &(base, count) in &chunks {
                    if offset < count {
                        address = Some(base + offset as u64);
                        break;
                    }
                    offset -= count;
                }
                let pointer = self.translate(address.unwrap(), 1, true);
                unsafe {
                    pointer.as_ptr().write((self.produced % 251) as u8);
                }
                self.produced += 1;
                self.cursor = (self.cursor + 1) % ring;
            }
            self.store(Bar::Hda, 0x84, self.cursor as u32);
            self.hda[0x83] |= 4;
        }
    }
    struct Regs(Arc<Mutex<Model>>);
    // SAFETY: isolated register state and pinned RAM, no native device effects;
    // all synchronous register/domain/DMA accesses share one serialized model.
    unsafe impl Registers for Regs {
        fn identity(&mut self) -> Result<Identity, Error> {
            Ok(Identity {
                vendor: 0x8086,
                device: 0xa0c8,
                revision: 1,
            })
        }
        fn bytes(&self, bar: Bar) -> usize {
            self.0.lock().unwrap().bytes(bar).len()
        }
        fn set_bus_master(&mut self, value: bool) -> Result<(), Error> {
            self.0.lock().unwrap().master = value;
            Ok(())
        }
        fn misc_clock_gate(&mut self, value: bool) -> Result<(), Error> {
            self.0.lock().unwrap().clock_gate = value;
            Ok(())
        }
        fn hold_d0(&mut self) -> Result<(), Error> {
            self.0.lock().unwrap().held_d0 = true;
            Ok(())
        }
        fn read8(&mut self, bar: Bar, offset: usize) -> Result<u8, Error> {
            Ok(self.0.lock().unwrap().bytes(bar)[offset])
        }
        fn read16(&mut self, bar: Bar, offset: usize) -> Result<u16, Error> {
            Ok(u16::from_le_bytes(
                self.0.lock().unwrap().bytes(bar)[offset..offset + 2]
                    .try_into()
                    .unwrap(),
            ))
        }
        fn read32(&mut self, bar: Bar, offset: usize) -> Result<u32, Error> {
            Ok(self.0.lock().unwrap().load(bar, offset))
        }
        fn write8(&mut self, bar: Bar, offset: usize, value: u8) -> Result<(), Error> {
            self.0.lock().unwrap().write8(bar, offset, value);
            Ok(())
        }
        fn write16(&mut self, bar: Bar, offset: usize, value: u16) -> Result<(), Error> {
            self.0.lock().unwrap().bytes_mut(bar)[offset..offset + 2]
                .copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        fn write32(&mut self, bar: Bar, offset: usize, value: u32) -> Result<(), Error> {
            self.0.lock().unwrap().write32(bar, offset, value);
            Ok(())
        }
    }
    struct Domain(Arc<Mutex<Model>>);
    // SAFETY: one synchronous isolated requester, actual retained CPU RAM and
    // symbolic nonidentity IOVAs; device accesses walk its actual BDL addresses.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &DmaPages,
            direction: DmaDirection,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            let mut model = self.0.lock().unwrap();
            let id = model.next;
            model.next += 1;
            let token = DomainMapping {
                id,
                address: 0x1_50000000 + id * 0x100000,
                bytes: pages.bytes(),
            };
            if token.address + token.bytes as u64 - 1 > limit {
                return Err(DmaError::AddressLimit);
            }
            let cpu = pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap();
            model.translations.push(Translation {
                token,
                cpu,
                _pin: pages.clone(),
                direction,
                device_owned: false,
            });
            Ok(token)
        }
        unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
            let mut model = self.0.lock().unwrap();
            if model.fail_unmap == Some(token.id) {
                return Err(DmaError::InvalidationFailed);
            }
            let index = model
                .translations
                .iter()
                .position(|t| t.token == token)
                .unwrap();
            model.translations.remove(index);
            model.unmaps += 1;
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            let mut model = self.0.lock().unwrap();
            let map = model
                .translations
                .iter_mut()
                .find(|t| t.token == token)
                .unwrap();
            assert_eq!(map.direction, direction);
            assert!(range.end <= token.bytes);
            map.device_owned = true;
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            let mut model = self.0.lock().unwrap();
            assert_eq!(
                model.hda[if direction == DmaDirection::FromDevice {
                    0x80
                } else {
                    0xa0
                }] & RUN,
                0
            );
            let map = model
                .translations
                .iter_mut()
                .find(|t| t.token == token)
                .unwrap();
            assert_eq!(map.direction, direction);
            assert!(range.end <= token.bytes);
            map.device_owned = false;
            Ok(())
        }
        unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
            let mut model = self.0.lock().unwrap();
            assert!(!model.master);
            assert_eq!(model.load(Bar::Dsp, ADSPCS) & 0x0f000000, 0);
            if model.fail_drain {
                return Err(DmaError::DrainUnavailable);
            }
            model.drained += 1;
            Ok(())
        }
    }
    struct Time(AtomicU64);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
        fn relax(&self) {
            self.0.fetch_add(10, Ordering::Relaxed);
        }
    }
    fn firmware() -> Catalog {
        let bytes = vec![0x5a; 4096];
        Catalog::from_handoff(vec![Resource {
            name: "sof-tgl.ri",
            target: target(),
            provenance: Provenance {
                source: "authored-isolated-model",
                revision: "1",
                member: "sof-tgl.ri",
                license: "GPL-2.0-only",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        }])
        .unwrap()
    }
    fn target() -> Target<'static> {
        Target {
            driver: "intel-dsp",
            hardware: "8086:a0c8",
            revision: "cavs2.5-ipc3",
            board: None,
        }
    }
    fn fixture() -> (
        Controller<Regs, Time>,
        Arc<Mutex<Model>>,
        Source,
        Arc<dyn DmaDomain>,
    ) {
        let model = Arc::new(Mutex::new(Model::new()));
        let domain = Arc::new(Domain(model.clone()));
        let source = Source {
            drops: Arc::new(AtomicUsize::new(0)),
            next: AtomicU64::new(0x90000000),
        };
        let mut controller = match Controller::claim(
            Regs(model.clone()),
            Time(AtomicU64::new(0)),
            Config {
                dma_address_bits: 64,
            },
        ) {
            Ok(c) => c,
            Err((error, _, _)) => panic!("claim {error:?}"),
        };
        controller.initialize().unwrap();
        let catalog = firmware();
        let image = catalog
            .load(Requirement {
                name: "sof-tgl.ri",
                target: target(),
                minimum_bytes: 4096,
            })
            .unwrap();
        controller.boot(image, &source, domain.clone()).unwrap();
        (controller, model, source, domain)
    }
    #[test]
    fn actual_bdl_nonidentity_dma_cold_boot_direct_dmic_wrap_pause_release_and_retire() {
        let (mut controller, model, source, domain) = fixture();
        assert_eq!(controller.firmware_report().unwrap().abi, 0x03017001);
        controller
            .install_dmic(topology::tests::topology())
            .unwrap();
        controller
            .prepare_capture(&source, domain, 8192, 4096)
            .unwrap();
        controller.start_capture().unwrap();
        let total = 8192 * 5 + 1232;
        model.lock().unwrap().advance(total);
        assert_eq!(controller.capture_position().unwrap(), total % 8192);
        assert_eq!(controller.read_capture(0, &mut [0; 8]), Err(Error::State));
        controller.stop_capture().unwrap();
        let mut captured = vec![0; 8192];
        controller.read_capture(0, &mut captured).unwrap();
        for (offset, sample) in captured.into_iter().enumerate() {
            let latest = total - 1 - ((total - 1 + 8192 - offset) % 8192);
            assert_eq!(sample, (latest % 251) as u8);
        }
        controller.start_capture().unwrap();
        model.lock().unwrap().advance(64);
        controller.stop_capture().unwrap();
        assert!(model.lock().unwrap().commands.contains(&0x60070000));
        controller.shutdown().unwrap();
        assert_eq!(controller.state(), State::Shutdown);
        assert!(model.lock().unwrap().translations.is_empty());
        assert_eq!(source.drops.load(Ordering::Relaxed), 6);
    }
    #[test]
    fn ipc_timeout_or_unacknowledged_dma_stop_retains_real_pins_and_blocks_new_submission() {
        let (mut controller, model, source, domain) = fixture();
        controller
            .install_dmic(topology::tests::topology())
            .unwrap();
        controller
            .prepare_capture(&source, domain, 8192, 4096)
            .unwrap();
        model.lock().unwrap().stall_reply = true;
        assert_eq!(controller.start_capture(), Err(Error::Timeout(Phase::Ipc)));
        assert_eq!(controller.start_capture(), Err(Error::NeedsReset));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        model.lock().unwrap().stall_stop = true;
        assert_eq!(controller.shutdown(), Err(Error::Timeout(Phase::StreamRun)));
        assert_eq!(model.lock().unwrap().unmaps, 0);
        {
            let mut state = model.lock().unwrap();
            state.stall_stop = false;
            state.stall_reply = false;
        }
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 6);
    }
    #[test]
    fn failed_real_remapper_drain_and_partial_unmap_can_retry_without_releasing_pins() {
        let (mut controller, model, source, _) = fixture();
        model.lock().unwrap().fail_drain = true;
        assert_eq!(
            controller.shutdown(),
            Err(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(model.lock().unwrap().unmaps, 0);
        {
            let mut state = model.lock().unwrap();
            state.fail_drain = false;
            state.fail_unmap = Some(1);
        }
        assert_eq!(
            controller.shutdown(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(model.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        model.lock().unwrap().fail_unmap = None;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 4);
    }
    #[test]
    fn original_firmware_payload_extent_and_unknown_cavs_clock_modes_are_explicit() {
        assert!(ipc::firmware_payload(&[0; 4095]).is_err());
        let mut image = vec![0; 32 + 4096];
        ipc::put(&mut image, 0, 0x6e614d58);
        ipc::put(&mut image, 4, 32);
        ipc::put(&mut image, 8, 16);
        ipc::put(&mut image, 12, 1 << 24);
        ipc::put(&mut image, 16, 6);
        ipc::put(&mut image, 20, 16);
        ipc::put(&mut image, 24, 1);
        assert_eq!(ipc::firmware_payload(&image).unwrap().len(), 4096);
        ipc::put(&mut image, 28, 1);
        assert!(ipc::firmware_payload(&image).is_err());
    }
    #[test]
    #[ignore = "STELA_INTEL_SOF_ORACLE: run intel_dsp/reference.py against unchanged pinned Linux first"]
    fn unchanged_linux_cnl_host_done_notification_acknowledgement() {
        let (mut controller, model, _, _) = fixture();
        let trace = std::fs::read_to_string(
            std::env::var("STELA_INTEL_SOF_ORACLE").expect("original Linux trace"),
        )
        .unwrap();
        let expected = trace
            .lines()
            .map(|line| {
                let mut fields = line.split_whitespace();
                (
                    usize::from_str_radix(fields.next().unwrap(), 16).unwrap(),
                    u32::from_str_radix(fields.next().unwrap(), 16).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let actual = model
            .lock()
            .unwrap()
            .writes
            .iter()
            .filter_map(|&(bar, offset, value)| {
                (bar == Bar::Dsp && matches!(offset, IPC_NOTIFY | IPC_NOTIFY_ACK))
                    .then_some((offset, value))
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        controller.shutdown().unwrap();
    }
}
