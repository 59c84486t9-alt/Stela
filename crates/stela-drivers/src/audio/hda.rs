// SPDX-License-Identifier: GPL-2.0-only
//! Polled standard HD Audio transport and PCM DMA, adapted from Linux
//! `sound/hda/core/{controller,stream,device}.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//!
//! This is the conventional HDA MMIO core. The `pci` module prepares a bounded
//! legacy Intel subset. Intel DSP/firmware ownership, other vendor quirks, ACPI
//! power resources, HDMI GPU coordination, OEM amplifier/pin policy, suspend and
//! guest audio bridging remain platform responsibilities. An ID match alone
//! does not establish exclusive controller ownership.
//! All DMA allocations live for the boot, even after an error or drop. Do not
//! unmap memory or release controller ownership until shutdown succeeds (or
//! the platform independently resets and quiesces the device).
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use super::{Error, Phase};
use crate::bus::{
    dma::{DmaAllocator, DmaBuffer},
    i2c::Timer,
};

mod codec;
pub mod pci;
mod registers;
mod routing;
mod stream;
pub use codec::{CodecGraph, FunctionGroup, PcmCapabilities, Verb, Widget, WidgetKind};
use registers::*;
pub use registers::{MmioRegisters, Registers};
pub use routing::{AnalogRoute, PinOptions, Vref};
use stream::Stream;
pub use stream::{StreamId, StreamStatus};

/// Select from an actual controller identity/quirk table in platform glue.
/// Intel/AMD standard reset uses the set-then-clear handshake; a self-clearing
/// controller must be explicitly identified, never inferred from a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorbReset {
    Handshake,
    SelfClearing,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub corb_reset: CorbReset,
    pub transition_timeout_us: u32,
    pub verb_timeout_us: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            corb_reset: CorbReset::Handshake,
            transition_timeout_us: 100_000,
            verb_timeout_us: 100_000,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub input_streams: u8,
    pub output_streams: u8,
    /// Reported but not allocated by this implementation.
    pub bidirectional_streams: u8,
    pub address_64_bit: bool,
    /// Word budgets per 48kHz link frame, on a single unstriped SDO/SDI.
    pub output_payload_words: u16,
    pub input_payload_words: u16,
    /// Zero means no additional per-stream limit.
    pub output_stream_payload_words: u16,
    pub input_stream_payload_words: u16,
}

pub struct Controller<R, T> {
    registers: R,
    timer: T,
    config: Config,
    capabilities: Capabilities,
    codec_mask: u16,
    corb: DmaBuffer,
    rirb: DmaBuffer,
    corb_entries: u16,
    rirb_entries: u16,
    corb_wp: u16,
    rirb_rp: u16,
    command_poisoned: bool,
    stopped: bool,
    streams: Vec<Option<Stream>>,
    routes: Vec<(StreamId, AnalogRoute)>,
    routing_failed: bool,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Claim and reset a controller, then start its CORB/RIRB DMA engines.
    ///
    /// # Safety
    /// The caller exclusively owns a powered, conventional HDA controller and
    /// all of its fixed/bidirectional stream descriptors. Registers must expose
    /// at least 0x440 bytes of uncached BAR0 using native access widths; no
    /// firmware, DSP, AML, SMM or other CPU may concurrently use the hardware.
    /// The allocator must return unique coherent identity-mapped contiguous
    /// memory reachable by this controller (including any IOMMU). Keep all DMA
    /// memory and MMIO alive for the boot. On constructor failure, quiesce/reset
    /// hardware before releasing ownership: stop acknowledgement may have failed.
    /// Apply platform PCI/snoop/power/clock/quirk setup before calling this.
    pub unsafe fn new(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
    ) -> Result<Self, Error> {
        if config.transition_timeout_us == 0 || config.verb_timeout_us == 0 {
            return Err(Error::InvalidConfiguration);
        }
        let mut registers = registers;
        let (major, minor) = (registers.read8(VMAJ), registers.read8(VMIN));
        if major != 1 || minor != 0 {
            return Err(Error::UnsupportedVersion { major, minor });
        }
        let gcap = registers.read16(GCAP);
        let capabilities = Capabilities {
            input_streams: ((gcap >> 8) & 15) as u8,
            output_streams: ((gcap >> 12) & 15) as u8,
            bidirectional_streams: ((gcap >> 3) & 31) as u8,
            address_64_bit: gcap & 1 != 0,
            output_payload_words: registers.read16(OUTPAY),
            input_payload_words: registers.read16(INPAY),
            output_stream_payload_words: registers.read16(OUTSTRMPAY),
            input_stream_payload_words: registers.read16(INSTRMPAY),
        };
        let total = capabilities.input_streams
            + capabilities.output_streams
            + capabilities.bidirectional_streams;
        if total == 0 || total > 30 {
            return Err(Error::UnsupportedTopology);
        }
        // Allocations remain alive if hardware refuses to stop on an error.
        let corb = allocator
            .allocate(1024, 128)
            .map_err(|_| Error::NoDmaMemory)?;
        let rirb = allocator
            .allocate(2048, 128)
            .map_err(|_| Error::NoDmaMemory)?;
        Self::check_dma(&corb, 128, capabilities.address_64_bit)?;
        Self::check_dma(&rirb, 128, capabilities.address_64_bit)?;
        if corb.len() < 1024 || rirb.len() < 2048 {
            return Err(Error::InvalidBuffer);
        }
        let mut controller = Self {
            registers,
            timer,
            config,
            capabilities,
            codec_mask: 0,
            corb,
            rirb,
            corb_entries: 0,
            rirb_entries: 0,
            corb_wp: 0,
            rirb_rp: 0,
            command_poisoned: false,
            stopped: false,
            streams: (0..total).map(|_| None).collect(),
            routes: Vec::new(),
            routing_failed: false,
        };
        if let Err(error) = controller.initialize() {
            let _ = controller.shutdown();
            return Err(error);
        }
        Ok(controller)
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    pub fn codec_mask(&self) -> u16 {
        self.codec_mask
    }

    pub(super) fn check_dma(buffer: &DmaBuffer, align: u64, address64: bool) -> Result<(), Error> {
        let end = buffer
            .physical()
            .checked_add(buffer.len() as u64)
            .ok_or(Error::DmaAddress)?;
        if buffer.physical() == 0
            || buffer.physical() & (align - 1) != 0
            || (!address64 && end > 1u64 << 32)
        {
            return Err(Error::DmaAddress);
        }
        Ok(())
    }

    pub(super) fn wait(
        &mut self,
        phase: Phase,
        mut predicate: impl FnMut(&mut R) -> bool,
    ) -> Result<(), Error> {
        let start = self.timer.now_us();
        loop {
            if predicate(&mut self.registers) {
                return Ok(());
            }
            if self.timer.now_us().wrapping_sub(start)
                >= u64::from(self.config.transition_timeout_us)
            {
                return Err(Error::Timeout(phase));
            }
            self.timer.relax();
        }
    }

    fn delay(&self, us: u64) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < us {
            self.timer.relax();
        }
    }

    fn stop_commands(&mut self) -> Result<(), Error> {
        self.registers.write8(CORBCTL, 0);
        self.registers.write8(RIRBCTL, 0);
        self.wait(Phase::CommandStop, |r| {
            r.read8(CORBCTL) & COMMAND_RUN == 0 && r.read8(RIRBCTL) & COMMAND_RUN == 0
        })
    }

    fn initialize(&mut self) -> Result<(), Error> {
        self.registers.write32(INTCTL, 0);
        self.registers.write16(WAKEEN, 0);
        for index in 0..self.streams.len() as u8 {
            self.stop_descriptor(index)?;
        }
        self.stop_commands()?;
        self.registers.write32(DPLBASE, 0);
        self.registers.write32(DPUBASE, 0);
        if self.registers.read32(GCTL) & GCTL_RESET != 0 {
            self.registers.write16(STATESTS, CODEC_MASK);
        }
        let gctl = self.registers.read32(GCTL) & !(GCTL_RESET | GCTL_UNSOL);
        self.registers.write32(GCTL, gctl);
        self.wait(Phase::LinkResetEnter, |r| r.read32(GCTL) & GCTL_RESET == 0)?;
        self.delay(500); // Linux: >=100us link/codec PLL reset assertion.
        self.registers.write32(GCTL, gctl | GCTL_RESET);
        self.wait(Phase::LinkResetExit, |r| r.read32(GCTL) & GCTL_RESET != 0)?;
        self.delay(1000); // Codec initialization requires >=540us after CRST.
        self.codec_mask = self.registers.read16(STATESTS) & CODEC_MASK;
        self.registers.write16(STATESTS, self.codec_mask);
        let (entries, encoding) = ring_size(self.registers.read8(CORBSIZE))?;
        self.corb_entries = entries;
        self.registers.write8(CORBSIZE, encoding);
        if self.registers.read8(CORBSIZE) & 3 != encoding {
            return Err(Error::UnsupportedRingSize);
        }
        let (entries, encoding) = ring_size(self.registers.read8(RIRBSIZE))?;
        self.rirb_entries = entries;
        self.registers.write8(RIRBSIZE, encoding);
        if self.registers.read8(RIRBSIZE) & 3 != encoding {
            return Err(Error::UnsupportedRingSize);
        }
        self.corb.bytes_mut().fill(0);
        self.rirb.bytes_mut().fill(0);
        self.registers
            .write32(CORBLBASE, self.corb.physical() as u32);
        self.registers
            .write32(CORBUBASE, (self.corb.physical() >> 32) as u32);
        self.registers
            .write32(RIRBLBASE, self.rirb.physical() as u32);
        self.registers
            .write32(RIRBUBASE, (self.rirb.physical() >> 32) as u32);
        self.registers.write16(CORBWP, 0);
        self.registers.write16(CORBRP, POINTER_RESET);
        match self.config.corb_reset {
            CorbReset::Handshake => {
                self.wait(Phase::CorbResetEnter, |r| {
                    r.read16(CORBRP) & POINTER_RESET != 0
                })?;
                self.registers.write16(CORBRP, 0);
            }
            CorbReset::SelfClearing => {}
        }
        self.wait(Phase::CorbResetExit, |r| r.read16(CORBRP) == 0)?;
        self.registers.write16(RIRBWP, POINTER_RESET);
        self.wait(Phase::RirbReset, |r| r.read16(RIRBWP) == 0)?;
        self.registers.write16(RINTCNT, 1);
        self.registers.write8(CORBSTS, CORB_MEMORY);
        self.registers.write8(RIRBSTS, RIRB_RESPONSE | RIRB_OVERRUN);
        fence(Ordering::SeqCst);
        // RIRB must be running before any CORB command can produce a reply.
        self.registers.write8(RIRBCTL, COMMAND_RUN);
        self.registers.write8(CORBCTL, COMMAND_RUN);
        self.wait(Phase::CommandStart, |r| {
            r.read8(CORBCTL) & COMMAND_RUN != 0 && r.read8(RIRBCTL) & COMMAND_RUN != 0
        })
    }

    fn command_fault(&mut self) -> Result<(), Error> {
        if self.registers.read8(CORBSTS) & CORB_MEMORY != 0 {
            return Err(Error::CorbMemory);
        }
        if self.registers.read8(RIRBSTS) & RIRB_OVERRUN != 0 {
            return Err(Error::RirbOverrun);
        }
        Ok(())
    }

    /// Exactly one outstanding solicited command across all codecs. A timeout
    /// poisons the transport: HDA responses have no transaction ID, so a late
    /// response cannot safely be matched to a later command for the same codec.
    pub fn verb(&mut self, verb: Verb) -> Result<u32, Error> {
        if self.stopped {
            return Err(Error::Shutdown);
        }
        if self.command_poisoned {
            return Err(Error::NeedsReset);
        }
        if self.codec_mask & (1 << verb.codec()) == 0 {
            return Err(Error::CodecAbsent);
        }
        let result = self.execute_verb(verb);
        if result.is_err() {
            self.command_poisoned = true;
            let _ = self.stop_commands();
        }
        result
    }

    fn responses(&mut self, expected: Option<u8>) -> Result<Option<u32>, Error> {
        self.command_fault()?;
        let wp = self.registers.read16(RIRBWP);
        if wp >= self.rirb_entries {
            return Err(Error::InvalidRingPointer);
        }
        fence(Ordering::Acquire);
        let mut response = None;
        while self.rirb_rp != wp {
            self.rirb_rp = (self.rirb_rp + 1) % self.rirb_entries;
            let offset = usize::from(self.rirb_rp) * 8;
            let extra = u32::from_le(self.rirb.read::<u32>(offset + 4));
            let value = u32::from_le(self.rirb.read::<u32>(offset));
            if extra & RESPONSE_UNSOL != 0 {
                continue;
            }
            let codec = (extra & 15) as u8;
            if expected != Some(codec) || response.is_some() {
                return Err(Error::UnexpectedResponse { codec });
            }
            response = Some(value);
        }
        // Read status after consuming DMA to avoid accepting data accompanied
        // by an overrun/memory fault. Only W1C the response bit here.
        self.command_fault()?;
        self.registers.write8(RIRBSTS, RIRB_RESPONSE);
        Ok(response)
    }

    fn execute_verb(&mut self, verb: Verb) -> Result<u32, Error> {
        self.responses(None)?; // stale solicited data must never satisfy this verb.
        let rp = self.registers.read16(CORBRP);
        if rp >= self.corb_entries {
            return Err(Error::InvalidRingPointer);
        }
        let next = (self.corb_wp + 1) % self.corb_entries;
        if next == rp {
            return Err(Error::InvalidRingPointer);
        }
        self.corb.write(usize::from(next) * 4, verb.raw().to_le());
        fence(Ordering::SeqCst);
        self.corb_wp = next;
        self.registers.write16(CORBWP, next);
        let start = self.timer.now_us();
        loop {
            if let Some(response) = self.responses(Some(verb.codec()))? {
                return Ok(response);
            }
            if self.timer.now_us().wrapping_sub(start) >= u64::from(self.config.verb_timeout_us) {
                return Err(Error::Timeout(Phase::Verb));
            }
            self.timer.relax();
        }
    }

    /// Stop every stream and both command engines. Failure retains ownership:
    /// DMA memory cannot be repurposed and the platform must reset the device.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.registers.write32(INTCTL, 0);
        let mut error = None;
        for index in 0..self.streams.len() as u8 {
            if let Err(fault) = self.stop_descriptor(index) {
                error.get_or_insert(fault);
            }
            if let Some(stream) = self.streams[usize::from(index)].as_mut() {
                stream.running = false;
                stream.poisoned = true;
            }
        }
        if let Err(fault) = self.stop_commands() {
            error.get_or_insert(fault);
        }
        self.command_poisoned = true;
        if let Some(error) = error {
            return Err(error);
        }
        self.registers.write32(DPLBASE, 0);
        self.registers.write32(DPUBASE, 0);
        self.stopped = true;
        Ok(())
    }
}

fn ring_size(capability: u8) -> Result<(u16, u8), Error> {
    if capability & (1 << 6) != 0 {
        Ok((256, 2))
    } else if capability & (1 << 5) != 0 {
        Ok((16, 1))
    } else if capability & (1 << 4) != 0 {
        Ok((2, 0))
    } else {
        Err(Error::UnsupportedRingSize)
    }
}

#[cfg(test)]
mod tests {
    //! Stateful register/DMA model exercising the production engine. It consumes
    //! CORB entries, publishes RIRB entries and walks the actual BDL/PCM memory.
    use super::*;
    use crate::{
        audio::{Direction, PcmFormat},
        bus::dma::RegionAllocator,
    };
    use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};

    #[derive(Clone)]
    struct ModelClock(Rc<Cell<u64>>);
    impl Timer for ModelClock {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get() + 1);
        }
    }

    struct Fixture {
        _backing: Vec<u64>,
        allocator: RegionAllocator,
    }
    impl Fixture {
        fn new() -> Self {
            let mut backing = vec![0u64; 256 * 1024];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: unique vector-backed RAM outlives the controller and all DMA.
            let allocator =
                unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
            Self {
                _backing: backing,
                allocator,
            }
        }
    }

    struct Event {
        due: u64,
        offset: usize,
        value: u32,
        bytes: usize,
    }
    struct Reply {
        due: u64,
        value: u32,
        extra: u32,
    }
    struct Model {
        bytes: [u8; 0x440],
        clock: ModelClock,
        hardware_delay: u64,
        consume_delay: u64,
        response_delay: u64,
        next_consume: u64,
        events: Vec<Event>,
        replies: Vec<Reply>,
        self_clear: bool,
        reset_enter_stuck: bool,
        reset_exit_stuck: bool,
        command_stop_stuck: bool,
        corb_reset_stuck: bool,
        stream_start_stuck: bool,
        stream_stop_stuck: bool,
        stream_reset_stuck: bool,
        drop_reply: bool,
        wrong_codec: bool,
        inject_unsolicited: bool,
        duplicate_reply: bool,
        rirb_reset_stuck: bool,
        commands: Vec<u32>,
        constant_reply: Option<u32>,
        parameters: BTreeMap<(u8, u8), u32>,
        connection_words: BTreeMap<(u8, u8), u32>,
        formats: BTreeMap<u8, u16>,
        bindings: BTreeMap<u8, u8>,
        route_controls: BTreeMap<(u8, u16), u8>,
        amplifiers: BTreeMap<(u8, bool, u8, u8), u8>,
        power_ready: BTreeMap<u8, u64>,
        power_delay: u64,
        power_stuck: bool,
        power_error: bool,
        reject_route_control: Option<u16>,
        reject_amplifier: bool,
        last_dma_time: u64,
        dma_step_bytes: usize,
        playback: Vec<u8>,
        capture_counter: u8,
        stream_descriptors_seen: usize,
        writes: Vec<(usize, u32, usize)>,
    }

    impl Model {
        fn new(entries: u16) -> Rc<RefCell<Self>> {
            let clock = ModelClock(Rc::new(Cell::new(0)));
            let mut model = Self {
                bytes: [0; 0x440],
                clock,
                hardware_delay: 2,
                consume_delay: 2,
                response_delay: 3,
                next_consume: 0,
                events: Vec::new(),
                replies: Vec::new(),
                self_clear: false,
                reset_enter_stuck: false,
                reset_exit_stuck: false,
                command_stop_stuck: false,
                corb_reset_stuck: false,
                stream_start_stuck: false,
                stream_stop_stuck: false,
                stream_reset_stuck: false,
                drop_reply: false,
                wrong_codec: false,
                inject_unsolicited: false,
                duplicate_reply: false,
                rirb_reset_stuck: false,
                commands: Vec::new(),
                constant_reply: Some(0x1234_abcd),
                parameters: BTreeMap::new(),
                connection_words: BTreeMap::new(),
                formats: BTreeMap::new(),
                bindings: BTreeMap::new(),
                route_controls: BTreeMap::new(),
                amplifiers: BTreeMap::new(),
                power_ready: BTreeMap::new(),
                power_delay: 12,
                power_stuck: false,
                power_error: false,
                reject_route_control: None,
                reject_amplifier: false,
                last_dma_time: 0,
                dma_step_bytes: 0,
                playback: Vec::new(),
                capture_counter: 0,
                stream_descriptors_seen: 0,
                writes: Vec::new(),
            };
            model.set(VMAJ, 1, 1);
            model.set(GCAP, (2 << 12) | (2 << 8) | 1, 2);
            model.set(OUTPAY, 60, 2);
            model.set(INPAY, 29, 2);
            model.set(GCTL, GCTL_RESET, 4);
            let capability = match entries {
                2 => 1 << 4,
                16 => 1 << 5,
                256 => 1 << 6,
                _ => panic!(),
            };
            model.set(CORBSIZE, capability, 1);
            model.set(RIRBSIZE, capability, 1);
            Rc::new(RefCell::new(model))
        }

        fn get(&self, offset: usize, bytes: usize) -> u32 {
            (0..bytes).fold(0, |value, index| {
                value | (u32::from(self.bytes[offset + index]) << (index * 8))
            })
        }
        fn set(&mut self, offset: usize, value: u32, bytes: usize) {
            for index in 0..bytes {
                self.bytes[offset + index] = (value >> (index * 8)) as u8;
            }
        }
        fn size(&self, offset: usize) -> u16 {
            match self.bytes[offset] & 3 {
                0 => 2,
                1 => 16,
                2 => 256,
                _ => panic!(),
            }
        }
        fn address(&self, low: usize, high: usize) -> u64 {
            u64::from(self.get(low, 4)) | (u64::from(self.get(high, 4)) << 32)
        }

        fn advance(&mut self) {
            let now = self.clock.now_us();
            let mut index = 0;
            while index < self.events.len() {
                if self.events[index].due > now {
                    index += 1;
                    continue;
                }
                let event = self.events.remove(index);
                let was_reset = self.get(GCTL, 4) & GCTL_RESET == 0;
                self.set(event.offset, event.value, event.bytes);
                if event.offset == GCTL && event.value & GCTL_RESET != 0 && was_reset {
                    self.set(STATESTS, 1, 2);
                }
            }
            if self.bytes[CORBCTL] & COMMAND_RUN != 0 && now >= self.next_consume {
                let rp = self.get(CORBRP, 2) as u16;
                let wp = self.get(CORBWP, 2) as u16;
                if rp < self.size(CORBSIZE) && rp != wp {
                    let next = (rp + 1) % self.size(CORBSIZE);
                    let address = self.address(CORBLBASE, CORBUBASE);
                    assert_ne!(address, 0);
                    // SAFETY: production programmed its live fixture-backed DMA.
                    let command =
                        unsafe { ((address as *const u32).add(usize::from(next))).read_volatile() }
                            .to_le();
                    self.commands.push(command);
                    self.set(CORBRP, u32::from(next), 2);
                    self.next_consume = now + self.consume_delay;
                    let response = self.reply_for(command);
                    if !self.drop_reply {
                        let codec = if self.wrong_codec { 1 } else { command >> 28 };
                        if self.inject_unsolicited {
                            self.replies.push(Reply {
                                due: now + self.response_delay,
                                value: 0xaaaa_5555,
                                extra: codec | RESPONSE_UNSOL,
                            });
                        }
                        self.replies.push(Reply {
                            due: now + self.response_delay,
                            value: response,
                            extra: codec,
                        });
                        if self.duplicate_reply {
                            self.replies.push(Reply {
                                due: now + self.response_delay,
                                value: response,
                                extra: codec,
                            });
                        }
                    }
                }
            }
            if self.bytes[RIRBCTL] & COMMAND_RUN != 0 {
                let mut index = 0;
                while index < self.replies.len() {
                    if self.replies[index].due > now {
                        index += 1;
                        continue;
                    }
                    let reply = self.replies.remove(index);
                    self.emit(reply.value, reply.extra);
                }
            }
            if now != self.last_dma_time {
                self.last_dma_time = now;
                if self.dma_step_bytes != 0 {
                    for index in 0..4 {
                        if self.bytes[stream_base(index) + SD_CTL] & SD_RUN != 0 {
                            self.dma_stream(index);
                        }
                    }
                }
            }
        }

        fn emit(&mut self, value: u32, extra: u32) {
            let next = (self.get(RIRBWP, 2) as u16 + 1) % self.size(RIRBSIZE);
            let address = self.address(RIRBLBASE, RIRBUBASE);
            assert_ne!(address, 0);
            // SAFETY: live unique fixture DMA is owned by the modeled device.
            unsafe {
                ((address as *mut u32).add(usize::from(next) * 2)).write_volatile(value.to_le());
                ((address as *mut u32).add(usize::from(next) * 2 + 1))
                    .write_volatile(extra.to_le());
            }
            self.set(RIRBWP, u32::from(next), 2);
            self.bytes[RIRBSTS] |= RIRB_RESPONSE;
        }

        fn reply_for(&mut self, command: u32) -> u32 {
            if let Some(value) = self.constant_reply {
                return value;
            }
            let node = ((command >> 20) & 127) as u8;
            let verb = ((command >> 8) & 0xfff) as u16;
            let long = (command >> 16) & 15;
            if long == 3 {
                let value = command as u16;
                let output = value & (1 << 15) != 0;
                assert_eq!(value & (1 << 14) != 0, !output);
                let index = ((value >> 8) & 15) as u8;
                if value & (1 << 13) != 0 {
                    self.amplifiers
                        .insert((node, output, index, 0), value as u8);
                }
                if value & (1 << 12) != 0 {
                    self.amplifiers
                        .insert((node, output, index, 1), value as u8);
                }
                return 0;
            }
            if long == 0xb {
                if self.reject_amplifier {
                    return 0xff;
                }
                let value = command as u16;
                let output = value & (1 << 15) != 0;
                let channel = u8::from(value & (1 << 13) == 0);
                return u32::from(
                    *self
                        .amplifiers
                        .get(&(node, output, value as u8 & 15, channel))
                        .unwrap_or(&0x80),
                );
            }
            match verb {
                0x705 => {
                    self.power_ready
                        .insert(node, self.clock.now_us() + self.power_delay);
                    0
                }
                0xf05 => {
                    if self.power_error {
                        1 << 8
                    } else if self.power_stuck
                        || self.clock.now_us() < *self.power_ready.get(&node).unwrap_or(&u64::MAX)
                    {
                        3 << 4
                    } else {
                        0
                    }
                }
                0x701 | 0x707 | 0x70c => {
                    self.route_controls
                        .insert((node, verb + 0x800), command as u8);
                    0
                }
                0xf01 | 0xf07 | 0xf0c => {
                    if self.reject_route_control == Some(verb) {
                        0xffff_ffff
                    } else {
                        u32::from(*self.route_controls.get(&(node, verb)).unwrap_or(&0))
                    }
                }

                0xf00 => *self.parameters.get(&(node, command as u8)).unwrap_or(&0),
                0xf02 => *self
                    .connection_words
                    .get(&(node, command as u8))
                    .unwrap_or(&0),
                0xf1c => 0x0101_4010,
                0x706 => {
                    self.bindings.insert(node, command as u8);
                    0
                }
                0xf06 => u32::from(*self.bindings.get(&node).unwrap_or(&0)),
                0xa00 => u32::from(*self.formats.get(&node).unwrap_or(&0)),
                _ if (command >> 16) & 15 == 2 => {
                    self.formats.insert(node, command as u16);
                    0
                }
                _ => 0,
            }
        }

        fn write(&mut self, offset: usize, value: u32, bytes: usize) {
            self.advance();
            self.writes.push((offset, value, bytes));
            if offset == STATESTS
                || offset == CORBSTS
                || offset == RIRBSTS
                || (offset >= 0x80 && (offset - 0x80) % 0x20 == SD_STS)
            {
                let old = self.get(offset, bytes);
                self.set(offset, old & !value, bytes);
                return;
            }
            if offset == CORBSIZE || offset == RIRBSIZE {
                self.bytes[offset] = (self.bytes[offset] & 0x70) | (value as u8 & 3);
                return;
            }
            if offset == CORBRP {
                if self.corb_reset_stuck {
                    return;
                }
                self.set(offset, if self.self_clear { 0 } else { value }, bytes);
                return;
            }
            if offset == RIRBWP && value & u32::from(POINTER_RESET) != 0 {
                if !self.rirb_reset_stuck {
                    self.set(offset, 0, bytes);
                }
                return;
            }
            if offset == GCTL {
                if (value & GCTL_RESET == 0 && self.reset_enter_stuck)
                    || (value & GCTL_RESET != 0 && self.reset_exit_stuck)
                {
                    return;
                }
                self.events.push(Event {
                    due: self.clock.now_us() + self.hardware_delay,
                    offset,
                    value,
                    bytes,
                });
                return;
            }
            if (offset == CORBCTL || offset == RIRBCTL)
                && value & u32::from(COMMAND_RUN) == 0
                && self.command_stop_stuck
            {
                return;
            }
            if offset >= 0x80 && (offset - 0x80).is_multiple_of(0x20) {
                assert_eq!(bytes, 1, "wide SD_CTL access aliases W1C status");
                let old = self.bytes[offset];
                if value as u8 & SD_RESET != 0 {
                    if self.stream_reset_stuck {
                        return;
                    }
                    self.set(offset + SD_LPIB, 0, 4);
                }
                if (value as u8 & SD_RUN != 0 && self.stream_start_stuck)
                    || (old & SD_RUN != 0 && value as u8 & SD_RUN == 0 && self.stream_stop_stuck)
                {
                    return;
                }
                self.events.push(Event {
                    due: self.clock.now_us() + self.hardware_delay,
                    offset,
                    value,
                    bytes,
                });
                return;
            }
            self.set(offset, value, bytes);
        }

        fn dma_stream(&mut self, index: u8) {
            let base = stream_base(index);
            let cbl = self.get(base + SD_CBL, 4) as usize;
            let lvi = self.get(base + SD_LVI, 2) as usize;
            let bdl = self.address(base + SD_BDLPL, base + SD_BDLPU);
            assert!(bdl.is_multiple_of(128) && bdl != 0 && lvi < 256);
            let mut descriptors = Vec::new();
            let mut total = 0;
            for entry in 0..=lvi {
                // SAFETY: BDL is a live production allocation in Fixture.
                let (address, len, ioc) = unsafe {
                    let ptr = (bdl as *const u8).add(entry * 16);
                    (
                        (ptr as *const u64).read_volatile(),
                        (ptr.add(8) as *const u32).read_volatile(),
                        (ptr.add(12) as *const u32).read_volatile(),
                    )
                };
                let len = len as usize;
                assert!(address.is_multiple_of(128) && len != 0 && len.is_multiple_of(128));
                assert!(
                    (address as usize & 4095) + len <= 4096,
                    "4K BDLE boundary crossed"
                );
                assert!(ioc <= 1);
                descriptors.push((address, len, ioc));
                total += len;
            }
            assert_eq!(total, cbl);
            self.stream_descriptors_seen += descriptors.len();
            let mut position = self.get(base + SD_LPIB, 4) as usize;
            for _ in 0..self.dma_step_bytes {
                let mut start = 0;
                let &(address, length, ioc) = descriptors
                    .iter()
                    .find(|(_, length, _)| {
                        let inside = position < start + length;
                        if !inside {
                            start += length;
                        }
                        inside
                    })
                    .unwrap();
                let address = (address + (position - start) as u64) as *mut u8;
                // SAFETY: only the stopped-owner API accesses this PCM allocation;
                // model transfers run synchronously while the register call polls.
                if index < 2 {
                    unsafe {
                        address.write_volatile(self.capture_counter);
                    }
                    self.capture_counter = self.capture_counter.wrapping_add(1);
                } else {
                    self.playback.push(unsafe { address.read_volatile() });
                }
                position += 1;
                if position == start + length && ioc != 0 {
                    self.bytes[base + SD_STS] |= SD_COMPLETE;
                }
                if position == cbl {
                    position = 0;
                }
            }
            self.set(base + SD_LPIB, position as u32, 4);
        }
    }

    #[derive(Clone)]
    struct ModelRegisters(Rc<RefCell<Model>>);
    impl Registers for ModelRegisters {
        fn read8(&mut self, offset: usize) -> u8 {
            let mut m = self.0.borrow_mut();
            m.advance();
            m.get(offset, 1) as u8
        }
        fn read16(&mut self, offset: usize) -> u16 {
            let mut m = self.0.borrow_mut();
            m.advance();
            m.get(offset, 2) as u16
        }
        fn read32(&mut self, offset: usize) -> u32 {
            let mut m = self.0.borrow_mut();
            m.advance();
            m.get(offset, 4)
        }
        fn write8(&mut self, offset: usize, value: u8) {
            self.0.borrow_mut().write(offset, u32::from(value), 1);
        }
        fn write16(&mut self, offset: usize, value: u16) {
            self.0.borrow_mut().write(offset, u32::from(value), 2);
        }
        fn write32(&mut self, offset: usize, value: u32) {
            self.0.borrow_mut().write(offset, value, 4);
        }
    }

    type Host = Controller<ModelRegisters, ModelClock>;
    fn config() -> Config {
        Config {
            transition_timeout_us: 50,
            verb_timeout_us: 30,
            ..Config::default()
        }
    }
    fn create(
        model: &Rc<RefCell<Model>>,
        fixture: &mut Fixture,
        config: Config,
    ) -> Result<Host, Error> {
        let timer = model.borrow().clock.clone();
        // SAFETY: model is the only device owner, DMA fixture stays alive in tests.
        unsafe {
            Controller::new(
                ModelRegisters(model.clone()),
                timer,
                &mut fixture.allocator,
                config,
            )
        }
    }
    fn verb() -> Verb {
        Verb::short(0, 0, 0xf00, 0).unwrap()
    }
    fn pcm() -> PcmFormat {
        PcmFormat {
            rate: 48_000,
            bits: 16,
            channels: 2,
        }
    }
    fn advance(model: &Rc<RefCell<Model>>, microseconds: u64) {
        for _ in 0..microseconds {
            let mut m = model.borrow_mut();
            m.clock.relax();
            m.advance();
        }
    }

    #[test]
    fn command_rings_wrap_at_all_finite_sizes_with_delayed_hardware() {
        for size in [2, 16, 256] {
            let mut fixture = Fixture::new();
            let model = Model::new(size);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            assert_eq!(controller.codec_mask(), 1);
            for _ in 0..600 {
                assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
            }
            let m = model.borrow();
            assert_eq!(m.commands.len(), 600);
            assert_eq!(m.get(CORBWP, 2), 600 % u32::from(size));
            assert_eq!(m.get(RIRBWP, 2), 600 % u32::from(size));
            assert_eq!(m.get(INTCTL, 4), 0);
            assert_eq!(m.get(GCTL, 4) & GCTL_UNSOL, 0);
        }
    }

    #[test]
    fn unsolicited_is_skipped_but_stale_wrong_and_duplicate_replies_are_not_accepted() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().inject_unsolicited = true;
        assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
        model.borrow_mut().emit(0x9999, 0);
        let count = model.borrow().commands.len();
        assert_eq!(
            controller.verb(verb()),
            Err(Error::UnexpectedResponse { codec: 0 })
        );
        assert_eq!(model.borrow().commands.len(), count);
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));

        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().wrong_codec = true;
        assert_eq!(
            controller.verb(verb()),
            Err(Error::UnexpectedResponse { codec: 1 })
        );
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
    }

    #[test]
    fn duplicate_solicited_reply_and_stuck_rirb_reset_fail_explicitly() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().duplicate_reply = true;
        assert_eq!(
            controller.verb(verb()),
            Err(Error::UnexpectedResponse { codec: 0 })
        );
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        let model = Model::new(16);
        model.borrow_mut().rirb_reset_stuck = true;
        model.borrow_mut().set(RIRBWP, 8, 2);
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::Timeout(Phase::RirbReset))
        ));
    }

    #[test]
    fn timed_out_verb_and_late_response_poison_until_platform_reset() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().response_delay = 80;
        assert_eq!(controller.verb(verb()), Err(Error::Timeout(Phase::Verb)));
        advance(&model, 100);
        // Even an otherwise matching late reply cannot be consumed by another verb.
        model.borrow_mut().emit(0x7777_7777, 0);
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        assert_eq!(model.borrow().commands.len(), 1);
        assert_eq!(model.borrow().get(CORBCTL, 1), 0);
        assert_eq!(model.borrow().get(RIRBCTL, 1), 0);
    }

    #[test]
    fn command_faults_and_invalid_pointers_are_explicit_and_poison() {
        for (offset, value, expected) in [
            (CORBSTS, 1, Error::CorbMemory),
            (RIRBSTS, 4, Error::RirbOverrun),
            (RIRBWP, 0xffff, Error::InvalidRingPointer),
            (CORBRP, 0xffff, Error::InvalidRingPointer),
        ] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            model.borrow_mut().set(
                offset,
                value,
                if offset == CORBRP || offset == RIRBWP {
                    2
                } else {
                    1
                },
            );
            assert_eq!(controller.verb(verb()), Err(expected));
            assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        }
    }

    #[test]
    fn link_reset_and_command_quiesce_fail_bounded_before_dma_start() {
        for (enter, expected) in [(true, Phase::LinkResetEnter), (false, Phase::LinkResetExit)] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            model.borrow_mut().reset_enter_stuck = enter;
            model.borrow_mut().reset_exit_stuck = !enter;
            assert!(
                matches!(create(&model, &mut fixture, config()), Err(Error::Timeout(phase)) if phase == expected)
            );
            assert_eq!(model.borrow().address(CORBLBASE, CORBUBASE), 0);
            assert!(model.borrow().clock.now_us() < 2000);
        }
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        {
            let mut m = model.borrow_mut();
            m.command_stop_stuck = true;
            m.set(CORBCTL, u32::from(COMMAND_RUN), 1);
        }
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::Timeout(Phase::CommandStop))
        ));
        assert_eq!(model.borrow().address(CORBLBASE, CORBUBASE), 0);
    }

    #[test]
    fn corb_reset_quirk_is_explicit_and_no_timeout_fallback_guesses_it() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        model.borrow_mut().self_clear = true;
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::Timeout(Phase::CorbResetEnter))
        ));
        let model = Model::new(16);
        model.borrow_mut().self_clear = true;
        let controller = create(
            &model,
            &mut fixture,
            Config {
                corb_reset: CorbReset::SelfClearing,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(controller.codec_mask(), 1);
    }

    fn graph_model() -> Rc<RefCell<Model>> {
        let model = Model::new(16);
        {
            let mut m = model.borrow_mut();
            m.constant_reply = None;
            for (node, parameter, value) in [
                (0, 0, 0x1234_5678),
                (0, 2, 0x0010_0100),
                (0, 4, (1 << 16) | 1),
                (1, 5, 1),
                (1, 0x0f, 1),
                (1, 4, (2 << 16) | 6),
                (1, 0x0a, (1 << 6) | (1 << 17)),
                (1, 0x0b, 1),
                (1, 0x0d, 0x8000_1234),
                (1, 0x12, 0x8000_5678),
                (2, 9, 1 | (1 << 2)), // stereo output, inherited output amp/PCM
                (3, 9, (1 << 20) | 1 | (1 << 8)),
                (3, 0x0e, 1),
                (4, 9, (4 << 20) | (1 << 8)),
                (4, 0x0e, 0x81),
                (4, 0x0c, 0x10),
                (5, 9, 4 << 20),
                (5, 0x0c, 0x20),
                (6, 9, (2 << 20) | (1 << 8)),
                (6, 0x0e, 2),
                (7, 9, (3 << 20) | (1 << 8)),
                (7, 0x0e, 0x82),
            ] {
                m.parameters.insert((node, parameter), value);
            }
            m.connection_words.insert((3, 0), 5);
            m.connection_words.insert((4, 0), 2); // long list
            m.connection_words.insert((6, 0), 2 | (0x84 << 8)); // short range2..4
            m.connection_words.insert((7, 0), 2 | (0x8004 << 16)); // long range2..4
        }
        model
    }

    #[test]
    fn codec_graph_expands_short_and_long_ranges_and_inherits_capabilities() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        assert_eq!(graph.vendor_id, 0x1234_5678);
        assert_eq!(graph.groups.len(), 1);
        assert_eq!(graph.widget(6).unwrap().connections, [2, 3, 4]);
        assert_eq!(graph.widget(7).unwrap().connections, [2, 3, 4]);
        assert_eq!(graph.widget(4).unwrap().connections, [2]);
        assert_eq!(graph.widget(2).unwrap().output_amplifier, Some(0x8000_5678));
        assert!(graph.widget(2).unwrap().pcm.supports(pcm()));
        assert_eq!(graph.widget(4).unwrap().pin_capabilities, Some(0x10));
        assert_eq!(graph.widget(2).unwrap().channels(), 2);
    }

    #[test]
    fn malformed_codec_counts_ranges_and_connection_targets_are_rejected() {
        for (node, parameter, value) in
            [(0, 4, (127 << 16) | 2), (1, 4, (1 << 16) | 6), (6, 0x0e, 1)]
        {
            let mut fixture = Fixture::new();
            let model = graph_model();
            model
                .borrow_mut()
                .parameters
                .insert((node, parameter), value);
            if node == 6 {
                model.borrow_mut().connection_words.insert((6, 0), 0x84);
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            assert!(matches!(
                controller.enumerate_codec(0),
                Err(Error::InvalidCodecGraph | Error::InvalidConnectionList)
            ));
        }
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().connection_words.insert((4, 0), 0x100); // long NID cannot be packed into verbs.
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        assert!(matches!(
            controller.enumerate_codec(0),
            Err(Error::InvalidConnectionList)
        ));
    }

    #[test]
    fn pcm_formats_buffers_directions_and_verb_widths_validate_before_programming() {
        for rate in [
            8000, 11025, 16000, 22050, 32000, 44100, 48000, 88200, 96000, 176400, 192000,
        ] {
            for bits in [8, 16, 20, 24, 32] {
                let format = PcmFormat {
                    rate,
                    bits,
                    channels: 2,
                };
                assert!(format.encode().is_ok());
                assert_eq!(
                    format.frame_bytes().unwrap(),
                    if bits == 8 {
                        2
                    } else if bits == 16 {
                        4
                    } else {
                        8
                    }
                );
            }
        }
        assert_eq!(
            PcmFormat {
                rate: 12_345,
                ..pcm()
            }
            .encode(),
            Err(Error::InvalidFormat)
        );
        assert_eq!(
            PcmFormat {
                channels: 0,
                ..pcm()
            }
            .encode(),
            Err(Error::InvalidFormat)
        );
        assert_eq!(Verb::short(15, 0, 0xf00, 0), Err(Error::InvalidVerb));
        assert_eq!(Verb::short(0, 128, 0xf00, 0), Err(Error::InvalidVerb));
        assert_eq!(Verb::long(0, 2, 2, 0x4011).unwrap().raw(), 0x0022_4011);
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let count = model.borrow().writes.len();
        for (period, periods) in [(0, 2), (127, 2), (128, 1), (4096, 257), (128 * 33, 256)] {
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    pcm(),
                    period,
                    periods,
                    &mut fixture.allocator
                ),
                Err(Error::InvalidBuffer)
            );
        }
        assert_eq!(model.borrow().writes.len(), count);
        let id = controller
            .allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        assert_eq!(id.descriptor_index(), 0);
        assert_eq!(controller.write_pcm(id, 0, &[0]), Err(Error::InvalidBuffer));
    }

    #[test]
    fn production_streams_walk_real_split_bdls_and_preserve_stopped_cpu_ownership() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let playback = controller
            .allocate_stream(Direction::Playback, pcm(), 1536, 4, &mut fixture.allocator)
            .unwrap();
        let capture = controller
            .allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        assert_eq!(playback.descriptor_index(), 2);
        assert_ne!(playback.tag(), capture.tag());
        let samples: Vec<u8> = (0..6144).map(|index| index as u8).collect();
        controller.write_pcm(playback, 0, &samples).unwrap();
        controller.start(playback).unwrap();
        controller.start(capture).unwrap();
        assert_eq!(
            controller.write_pcm(playback, 0, &[1]),
            Err(Error::StreamRunning)
        );
        assert_eq!(
            controller.read_pcm(capture, 0, &mut [0]),
            Err(Error::StreamRunning)
        );
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 100);
        let status = controller.status(playback).unwrap();
        assert!(status.running && status.period_completed);
        assert!(status.position_bytes < 6144);
        assert!(!controller.status(playback).unwrap().period_completed);
        controller.stop(playback).unwrap();
        controller.stop(capture).unwrap();
        let m = model.borrow();
        assert!(m.stream_descriptors_seen > 5);
        assert!(m.playback.len() > 6144);
        for (index, byte) in m.playback.iter().enumerate() {
            assert_eq!(*byte, samples[index % samples.len()]);
        }
        drop(m);
        let mut captured = [0; 256];
        controller.read_pcm(capture, 0, &mut captured).unwrap();
        assert_eq!(captured, core::array::from_fn(|index| index as u8));
        assert_eq!(
            controller.read_pcm(capture, usize::MAX, &mut [0]),
            Err(Error::InvalidBuffer)
        );
        controller.shutdown().unwrap();
        assert_eq!(controller.start(playback), Err(Error::Shutdown));
    }

    #[test]
    fn stream_dma_faults_w1c_status_and_stop_failure_do_not_release_buffer_ownership() {
        for fault in [SD_FIFO_ERROR, SD_DESC_ERROR] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let id = controller
                .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
                .unwrap();
            controller.start(id).unwrap();
            model.borrow_mut().bytes[stream_base(id.descriptor_index()) + SD_STS] = 0x80 | fault;
            assert_eq!(
                controller.status(id),
                Err(Error::StreamDma {
                    status: 0x80 | fault
                })
            );
            assert_eq!(
                model.borrow().bytes[stream_base(id.descriptor_index()) + SD_STS],
                0x80
            );
            assert_eq!(controller.write_pcm(id, 0, &[0]), Err(Error::NeedsReset));
        }
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller.start(id).unwrap();
        model.borrow_mut().stream_stop_stuck = true;
        assert_eq!(controller.stop(id), Err(Error::Timeout(Phase::StreamStop)));
        assert_eq!(controller.write_pcm(id, 0, &[0]), Err(Error::NeedsReset));
        assert_eq!(
            controller.shutdown(),
            Err(Error::Timeout(Phase::StreamStop))
        );
        assert_ne!(
            model.borrow().get(stream_base(id.descriptor_index()), 1) & u32::from(SD_RUN),
            0
        );
    }

    #[test]
    fn stream_reset_start_and_position_failures_are_explicit() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().stream_reset_stuck = true;
        assert_eq!(
            controller.allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator),
            Err(Error::Timeout(Phase::StreamResetEnter))
        );
        model.borrow_mut().stream_reset_stuck = false;
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        model.borrow_mut().stream_start_stuck = true;
        assert_eq!(
            controller.start(id),
            Err(Error::Timeout(Phase::StreamStart))
        );
        assert_eq!(controller.write_pcm(id, 0, &[0]), Err(Error::NeedsReset));

        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        model
            .borrow_mut()
            .set(stream_base(id.descriptor_index()) + SD_LPIB, 256, 4);
        assert_eq!(controller.position(id), Ok(0));
        assert_eq!(controller.status(id).unwrap().position_bytes, 0);
        controller.start(id).unwrap(); // Terminal/wrap position is valid here too.
        controller.stop(id).unwrap();
        model
            .borrow_mut()
            .set(stream_base(id.descriptor_index()) + SD_LPIB, 257, 4);
        assert_eq!(controller.position(id), Err(Error::InvalidPosition(257)));
    }

    #[test]
    fn standard_converter_bind_checks_graph_direction_format_and_readback() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller.bind_converter(&graph, 2, id, 0).unwrap();
        assert_eq!(model.borrow().formats.get(&2), Some(&0x11));
        assert_eq!(model.borrow().bindings.get(&2), Some(&(id.tag() << 4)));
        assert_eq!(
            controller.bind_converter(&graph, 3, id, 0),
            Err(Error::UnsupportedTopology)
        );
        let unsupported = controller
            .allocate_stream(
                Direction::Playback,
                PcmFormat {
                    rate: 96_000,
                    ..pcm()
                },
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        assert_eq!(
            controller.bind_converter(&graph, 2, unsupported, 0),
            Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn dma_width_ring_capabilities_and_platform_claim_bounds_are_checked() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        model.borrow_mut().bytes[GCAP] &= !1;
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::DmaAddress)
        ));
        let model = Model::new(16);
        model.borrow_mut().bytes[CORBSIZE] = 0;
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::UnsupportedRingSize)
        ));
        // SAFETY: these invalid ranges are rejected before any MMIO is touched.
        assert!(unsafe { MmioRegisters::claim(0, 0x1000) }.is_err());
        assert!(unsafe { MmioRegisters::claim(0x1000, 0x400) }.is_err());
    }

    #[test]
    fn converter_channel_span_is_validated_before_any_verb_or_mmio() {
        for (widget_capabilities, channels, channel, expected) in [
            (1, 2, 1, Err(Error::InvalidFormat)),
            (1, 1, 0, Err(Error::InvalidFormat)),
            (1 | (1 << 13), 4, 0, Err(Error::UnsupportedTopology)),
            (0, 2, 1, Ok(())), // mono converter consumes only channel1.
            (1, 4, 2, Ok(())), // stereo converter consumes channels2 and3.
        ] {
            let mut fixture = Fixture::new();
            let model = graph_model();
            model
                .borrow_mut()
                .parameters
                .insert((2, 9), widget_capabilities);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let id = controller
                .allocate_stream(
                    Direction::Playback,
                    PcmFormat { channels, ..pcm() },
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let commands = model.borrow().commands.len();
            let writes = model.borrow().writes.len();
            assert_eq!(controller.bind_converter(&graph, 2, id, channel), expected);
            if expected.is_err() {
                assert_eq!(model.borrow().commands.len(), commands);
                assert_eq!(model.borrow().writes.len(), writes);
            }
        }
    }

    #[test]
    fn cyclic_buffers_require_complete_packets_at_high_and_fractional_rates() {
        for rate in [176_400, 192_000] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let format = PcmFormat {
                rate,
                bits: 32,
                channels: 16,
            };
            let writes = model.borrow().writes.len();
            let remaining = fixture.allocator.remaining();
            // Six 64-byte frames are not an integer number of four-frame packets.
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    format,
                    128,
                    3,
                    &mut fixture.allocator
                ),
                Err(Error::InvalidBuffer)
            );
            assert_eq!(model.borrow().writes.len(), writes);
            assert_eq!(fixture.allocator.remaining(), remaining);
            // A smaller supported stream has complete packets at the boundary.
            let format = PcmFormat {
                channels: 2,
                ..format
            };
            assert!(
                controller
                    .allocate_stream(Direction::Playback, format, 128, 3, &mut fixture.allocator)
                    .is_ok()
            );
        }
        // 32kHz transmits two blocks every third link frame, not one block.
        let format = PcmFormat {
            rate: 32_000,
            bits: 32,
            channels: 16,
        };
        assert_eq!(format.packet_bytes(), Ok(128));
    }

    #[test]
    fn unstriped_peak_and_aggregate_bandwidth_are_reserved_before_allocation() {
        for rate in [176_400, 192_000] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let writes = model.borrow().writes.len();
            let remaining = fixture.allocator.remaining();
            // Complete packets, but 128 words cannot fit the 60-word SDO0.
            let format = PcmFormat {
                rate,
                bits: 32,
                channels: 16,
            };
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    format,
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::LinkBandwidth {
                    required_words: 128,
                    available_words: 60
                })
            );
            assert_eq!(model.borrow().writes.len(), writes);
            assert_eq!(fixture.allocator.remaining(), remaining);
        }

        let mut fixture = Fixture::new();
        let model = Model::new(16);
        model.borrow_mut().set(OUTSTRMPAY, 3, 2);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        assert_eq!(
            controller.allocate_stream(
                Direction::Playback,
                PcmFormat { bits: 32, ..pcm() },
                128,
                2,
                &mut fixture.allocator
            ),
            Err(Error::LinkBandwidth {
                required_words: 4,
                available_words: 3
            })
        );

        let model = Model::new(16);
        model.borrow_mut().set(OUTPAY, 8, 2);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let format = PcmFormat {
            channels: 6,
            ..pcm()
        };
        controller
            .allocate_stream(Direction::Playback, format, 384, 2, &mut fixture.allocator)
            .unwrap();
        let remaining = fixture.allocator.remaining();
        let writes = model.borrow().writes.len();
        assert_eq!(
            controller.allocate_stream(Direction::Playback, format, 384, 2, &mut fixture.allocator),
            Err(Error::LinkBandwidth {
                required_words: 6,
                available_words: 2
            })
        );
        assert_eq!(fixture.allocator.remaining(), remaining);
        assert_eq!(model.borrow().writes.len(), writes);

        let format = PcmFormat {
            rate: 192_000,
            bits: 32,
            channels: 6,
        };
        assert_eq!(
            controller.allocate_stream(Direction::Capture, format, 384, 2, &mut fixture.allocator),
            Err(Error::LinkBandwidth {
                required_words: 49,
                available_words: 29
            })
        );
    }
    fn analog_model() -> Rc<RefCell<Model>> {
        let model = graph_model();
        {
            let mut m = model.borrow_mut();
            m.parameters.insert((1, 0x0d), 0x8000_1f1f);
            m.parameters.insert((1, 0x12), 0x8000_1f1f);
            for (node, parameter, value) in [
                (2, 9, 1 | (1 << 2) | (1 << 10)),
                (2, 0x0f, 1),
                (3, 9, (1 << 20) | 1 | (1 << 1) | (1 << 8)),
                (4, 9, (4 << 20) | 1 | (1 << 2) | (1 << 8)),
                (4, 0x0c, 0x18 | (1 << 16)),
                (5, 9, (4 << 20) | 1 | (1 << 1)),
                (5, 0x0c, 0x20 | (0x37 << 8)),
                (6, 9, (2 << 20) | 1 | (1 << 1) | (1 << 2) | (1 << 8)),
                (7, 9, (3 << 20) | 1 | (1 << 8)),
                (7, 0x0e, 2),
            ] {
                m.parameters.insert((node, parameter), value);
            }
            m.connection_words.insert((4, 0), 7);
            m.connection_words.insert((6, 0), 2 | (3 << 8));
            m.connection_words.insert((7, 0), 6 | (2 << 8));
            m.route_controls.insert((4, 0xf0c), 5); // Preserve BTL and L/R bits.
        }
        model
    }

    fn stereo() -> PcmFormat {
        PcmFormat {
            rate: 48_000,
            bits: 16,
            channels: 2,
        }
    }

    #[test]
    fn analog_routes_program_real_command_rings_power_mixers_pins_and_both_directions() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
        assert_eq!(output.nodes(), &[4, 7, 6, 2]);
        assert_eq!(input.nodes(), &[3, 5]);
        let playback = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let capture = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &output,
                playback,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: Some(true),
                },
            )
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &input,
                capture,
                0,
                PinOptions::Capture {
                    vref: Vref::EightyPercent,
                },
            )
            .unwrap();
        let m = model.borrow();
        assert_eq!(m.route_controls[&(4, 0xf07)], 0xc0);
        assert_eq!(m.route_controls[&(4, 0xf0c)], 7);
        assert_eq!(m.route_controls[&(5, 0xf07)], 0x24);
        assert_eq!(m.route_controls[&(7, 0xf01)], 0);
        for channel in 0..2 {
            assert_eq!(m.amplifiers[&(2, true, 0, channel)], 0x1f);
            assert_eq!(m.amplifiers[&(6, false, 0, channel)], 0x1f);
            assert_eq!(m.amplifiers[&(6, false, 1, channel)], 0x9f);
            assert_eq!(m.amplifiers[&(5, false, 0, channel)], 0x1f);
        }
        assert!(m.power_ready.contains_key(&1));
        assert!(m.power_ready.contains_key(&2));
        assert!(
            m.commands
                .iter()
                .filter(|command| (**command >> 8) & 0xfff == 0xf05)
                .count()
                > 3
        );
        assert_eq!(m.bindings[&2], playback.tag() << 4);
        assert_eq!(m.bindings[&3], capture.tag() << 4);
    }

    #[test]
    fn analog_route_preflight_refuses_unsupported_electrical_caps_before_any_verb() {
        for failure in 0..7 {
            let mut fixture = Fixture::new();
            let model = analog_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let mut graph = controller.enumerate_codec(0).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let playback = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let mut options = PinOptions::Playback {
                headphone: false,
                eapd: None,
            };
            match failure {
                0 => {
                    options = PinOptions::Playback {
                        headphone: true,
                        eapd: None,
                    };
                    graph.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 4)
                        .unwrap()
                        .pin_capabilities = Some(0x10);
                }
                1 => {
                    options = PinOptions::Playback {
                        headphone: false,
                        eapd: Some(true),
                    };
                    graph.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 4)
                        .unwrap()
                        .pin_capabilities = Some(0x10);
                }
                2 => graph.groups[0].power_states = Some(0),
                3 => {
                    graph.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 6)
                        .unwrap()
                        .input_amplifier = Some(0x1f1f)
                }
                4 => {
                    graph.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 6)
                        .unwrap()
                        .output_amplifier = Some(0x8000_0001)
                }
                5 => {
                    graph.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 7)
                        .unwrap()
                        .capabilities |= 1 << 13
                }
                _ => {
                    options = PinOptions::Capture {
                        vref: Vref::HighImpedance,
                    }
                }
            }
            let count = model.borrow().commands.len();
            assert!(
                controller
                    .configure_analog_route(&graph, &route, playback, 0, options)
                    .is_err()
            );
            assert_eq!(model.borrow().commands.len(), count);
            assert!(!controller.routing_failed);
        }
    }

    #[test]
    fn analog_route_cycles_digital_and_cross_group_endpoints_refuse_explicitly() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        for variant in 0..4 {
            let mut altered = graph.clone();
            match variant {
                0 => {
                    altered.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 2)
                        .unwrap()
                        .capabilities |= 1 << 9
                }
                1 => {
                    altered.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 6)
                        .unwrap()
                        .connections = vec![4, 7];
                    altered.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 7)
                        .unwrap()
                        .connections = vec![6];
                }
                2 => {
                    altered.groups[0]
                        .widgets
                        .iter_mut()
                        .find(|w| w.node == 4)
                        .unwrap()
                        .connections = vec![3]
                }
                _ => {
                    let removed = altered.groups[0].widgets.remove(0);
                    let mut extra = altered.groups[0].clone();
                    extra.node = 8;
                    extra.widgets = vec![removed];
                    altered.groups.push(extra);
                }
            }
            assert!(altered.analog_route(Direction::Playback, 4, 2).is_err());
        }
    }

    #[test]
    fn analog_route_hardware_failures_poison_future_configuration_and_start() {
        for failure in 0..6 {
            let mut fixture = Fixture::new();
            let model = analog_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let playback = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            {
                let mut m = model.borrow_mut();
                match failure {
                    0 => m.power_stuck = true,
                    1 => m.power_error = true,
                    2 => m.reject_route_control = Some(0xf01),
                    3 => m.reject_route_control = Some(0xf07),
                    4 => m.reject_route_control = Some(0xf0c),
                    _ => m.reject_amplifier = true,
                }
            }
            let result = controller.configure_analog_route(
                &graph,
                &route,
                playback,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: Some(true),
                },
            );
            assert_eq!(
                result,
                Err(if failure == 0 {
                    Error::Timeout(Phase::CodecPower)
                } else {
                    Error::RouteRejected
                })
            );
            assert_eq!(controller.start(playback), Err(Error::NeedsReset));
            assert_eq!(
                controller.configure_analog_route(
                    &graph,
                    &route,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None
                    }
                ),
                Err(Error::NeedsReset)
            );
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn analog_routes_reserve_widgets_and_require_every_stream_stopped() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let first = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let second = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let options = PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        controller
            .configure_analog_route(&graph, &route, first, 0, options)
            .unwrap();
        let count = model.borrow().commands.len();
        let original_binding = model.borrow().bindings[&2];
        assert_eq!(
            controller.bind_converter(&graph, 2, second, 0),
            Err(Error::RouteInUse)
        );
        assert_eq!(
            controller.bind_converter(&graph, 2, first, 0),
            Err(Error::RouteInUse)
        );
        assert_eq!(model.borrow().bindings[&2], original_binding);
        assert_eq!(model.borrow().commands.len(), count);
        assert_eq!(
            controller.configure_analog_route(&graph, &route, second, 0, options),
            Err(Error::RouteInUse)
        );
        assert_eq!(
            controller.configure_analog_route(&graph, &route, first, 0, options),
            Err(Error::RouteInUse)
        );
        controller.start(first).unwrap();
        assert_eq!(
            controller.configure_analog_route(&graph, &route, second, 0, options),
            Err(Error::StreamRunning)
        );
        assert_eq!(model.borrow().commands.len(), count);
        controller.stop(first).unwrap();
    }

    #[test]
    fn capture_bias_choices_and_stopped_buffer_fill_observe_capability_and_dma_ownership() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let mut graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Capture, 5, 3).unwrap();
        let capture = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        let playback = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        graph.groups[0]
            .widgets
            .iter_mut()
            .find(|w| w.node == 5)
            .unwrap()
            .pin_capabilities = Some(0x20);
        let count = model.borrow().commands.len();
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &route,
                capture,
                0,
                PinOptions::Capture { vref: Vref::Half }
            ),
            Err(Error::InvalidPinControl)
        );
        assert_eq!(model.borrow().commands.len(), count);
        controller
            .configure_analog_route(
                &graph,
                &route,
                capture,
                0,
                PinOptions::Capture {
                    vref: Vref::HighImpedance,
                },
            )
            .unwrap();
        assert_eq!(model.borrow().route_controls[&(5, 0xf07)], 0x20);
        controller.fill_capture(capture, 0xa5).unwrap();
        let mut bytes = [0; 256];
        controller.read_pcm(capture, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0xa5; 256]);
        assert_eq!(
            controller.fill_capture(playback, 0xa5),
            Err(Error::InvalidStream)
        );
        model.borrow_mut().dma_step_bytes = 64;
        controller.start(capture).unwrap();
        assert_eq!(
            controller.fill_capture(capture, 0),
            Err(Error::StreamRunning)
        );
        for _ in 0..8 {
            controller.timer.relax();
            let _ = controller.position(capture).unwrap();
        }
        controller.stop(capture).unwrap();
        controller.read_pcm(capture, 0, &mut bytes).unwrap();
        assert_ne!(bytes, [0xa5; 256]);
    }
    #[test]
    fn zero_widget_power_states_inherit_function_group_but_zero_group_refuses() {
        for group_states in [1, 0] {
            let mut fixture = Fixture::new();
            let model = analog_model();
            model
                .borrow_mut()
                .parameters
                .insert((1, 0x0f), group_states);
            model.borrow_mut().parameters.insert((2, 0x0f), 0);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            assert_eq!(graph.widget(2).unwrap().power_states, Some(group_states));
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let before = model.borrow().commands.len();
            let result = controller.configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: None,
                },
            );
            if group_states == 0 {
                assert_eq!(result, Err(Error::UnsupportedTopology));
                assert_eq!(model.borrow().commands.len(), before);
            } else {
                result.unwrap();
                assert!(model.borrow().power_ready.contains_key(&2));
            }
        }
    }
    #[test]
    fn uncertain_stream_stop_blocks_other_routes_before_codec_or_mmio_writes() {
        for dma_error in [false, true] {
            let mut fixture = Fixture::new();
            let model = analog_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let first = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let second = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller.start(first).unwrap();
            model.borrow_mut().stream_stop_stuck = true;
            if dma_error {
                model.borrow_mut().bytes[stream_base(first.descriptor_index()) + SD_STS] =
                    SD_DESC_ERROR;
                assert_eq!(
                    controller.status(first),
                    Err(Error::StreamDma {
                        status: SD_DESC_ERROR
                    })
                );
            } else {
                assert_eq!(
                    controller.stop(first),
                    Err(Error::Timeout(Phase::StreamStop))
                );
            }
            assert_ne!(
                model.borrow().bytes[stream_base(first.descriptor_index()) + SD_CTL] & SD_RUN,
                0
            );
            let commands = model.borrow().commands.len();
            let writes = model.borrow().writes.len();
            assert_eq!(
                controller.configure_analog_route(
                    &graph,
                    &route,
                    second,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None
                    }
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(model.borrow().commands.len(), commands);
            assert_eq!(model.borrow().writes.len(), writes);
        }
    }
}
