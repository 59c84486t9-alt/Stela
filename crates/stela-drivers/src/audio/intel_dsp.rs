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
    dma_contained: bool,
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
            dma_contained: true,
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
            self.dma_contained = false;
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
            self.complete_stopped_dma()?;
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
            self.complete_stopped_dma()?;
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
    #[allow(
        clippy::result_large_err,
        reason = "Incomplete shutdown must return the entire owned controller for retry without allocating or releasing uncertain register/DMA owners"
    )]
    pub fn into_stopped_resources(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            return Err(self);
        }
        Ok((self.registers, self.timer))
    }
}

#[cfg(test)]
mod tests;
