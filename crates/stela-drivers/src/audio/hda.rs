// SPDX-License-Identifier: GPL-2.0-only
//! Polled standard HD Audio transport and PCM DMA, adapted from Linux
//! `sound/hda/core/{controller,stream,device}.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//!
//! This is the conventional HDA MMIO core. The `pci` module prepares a bounded
//! conventional Intel/ATI/AMD subset. Intel DSP/firmware ownership, other vendor quirks, ACPI
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
mod conexant;
pub use conexant::{
    ConexantEapdMode, ConexantHeadsetInitialization, ConexantHeadsetKind, ConexantHeadsetReport,
    ConexantReport,
};
mod extended;
pub use extended::LinkClock;
mod lifecycle;
pub mod pci;
mod pins;
mod registers;
pub use pins::{AnalogEndpoint, PinConfiguration, PinConnection, PinDevice, PinSense};
mod realtek;
pub use realtek::{
    Alc269CommonReport, Alc269Variant, CoefficientChange, RealtekCommonReport,
    RealtekDualHeadphoneReport, RealtekHeadphoneReport, RealtekHeadphoneRoute,
};
mod routing;
mod sigmatel;
pub use sigmatel::{SigmatelGpio, SigmatelProfile, SigmatelReport};
mod stream;
pub use codec::{CodecGraph, FunctionGroup, PcmCapabilities, Verb, Widget, WidgetKind};
pub use lifecycle::{CodecDiscovery, CodecFailure, DiscoveryFailure, ProbePolicy};
use registers::*;
pub use registers::{MmioRegisters, Registers};
pub use routing::{AnalogRoute, PinOptions, Vref};
use stream::Stream;
pub use stream::{PositionInfo, PositionPolicy, StreamId, StreamStatus, StreamTagPolicy};

/// Select from an actual controller identity/quirk table in platform glue.
/// Intel/AMD standard reset uses the set-then-clear handshake; a self-clearing
/// controller must be explicitly identified, never inferred from a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorbReset {
    Handshake,
    SelfClearing,
}

/// Mandatory reset preparation selected from an actual controller identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResetPolicy {
    #[default]
    Generic,
    /// Native PCI CGCTL48 bit6 clock-gating bracket on every full reset.
    IntelClockGate,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub corb_reset: CorbReset,
    pub reset_policy: ResetPolicy,
    /// Identity/platform-selected DMA address ceiling, in addition to GCAP.
    /// This does not establish IOMMU reachability or coherency. Valid 32..=64.
    pub dma_address_bits: u8,
    pub position_policy: PositionPolicy,
    pub probe_policy: ProbePolicy,
    pub stream_tag_policy: StreamTagPolicy,
    pub transition_timeout_us: u32,
    pub verb_timeout_us: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            corb_reset: CorbReset::Handshake,
            reset_policy: ResetPolicy::Generic,
            dma_address_bits: 64,
            position_policy: PositionPolicy::Link,
            probe_policy: ProbePolicy::Once,
            stream_tag_policy: StreamTagPolicy::Global,
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
    /// Effective DMA ceiling after intersecting GCAP with the identity contract.
    pub dma_address_bits: u8,
    /// Word budgets per 48kHz link frame, on a single unstriped SDO/SDI.
    pub output_payload_words: u16,
    pub input_payload_words: u16,
    /// Zero means no additional per-stream limit.
    pub output_stream_payload_words: u16,
    pub input_stream_payload_words: u16,
}

/// DMA allocation identity plus a non-recycled reset generation. Metadata and
/// stream handles from another controller/reset must never program this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControllerToken {
    owner: u64,
    generation: u64,
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
    // Non-route codec controls: owner, codec address, actual node. Observing or
    // preconditioning a pin does not fabricate a converter path for it.
    codec_controls: Vec<(StreamId, u8, u8)>,
    conexant_codecs: Vec<conexant::State>,
    sigmatel_codecs: Vec<sigmatel::State>,
    routing_failed: bool,
    token: ControllerToken,
    lifecycle_failed: bool,
    discovery_ready: bool,
    extended: Option<extended::ExtendedCapabilities>,
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
    /// `config.dma_address_bits` must reflect the actual identity/platform DMA
    /// reachability ceiling; GCAP's 64-bit flag alone does not establish it.
    pub unsafe fn new(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
    ) -> Result<Self, Error> {
        if config.transition_timeout_us == 0
            || config.verb_timeout_us == 0
            || !(32..=64).contains(&config.dma_address_bits)
        {
            return Err(Error::InvalidConfiguration);
        }
        config.probe_policy.budget()?;
        registers.validate_config(&config)?;
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
            dma_address_bits: config
                .dma_address_bits
                .min(if gcap & 1 != 0 { 64 } else { 32 }),
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
        let extended = if config.reset_policy == ResetPolicy::IntelClockGate {
            Some(extended::inspect(&mut registers, total)?)
        } else {
            None
        };
        // Allocations remain alive if hardware refuses to stop on an error.
        let corb = allocator
            .allocate(1024, 128)
            .map_err(|_| Error::NoDmaMemory)?;
        let rirb = allocator
            .allocate(2048, 128)
            .map_err(|_| Error::NoDmaMemory)?;
        Self::check_dma(&corb, 128, capabilities.dma_address_bits)?;
        Self::check_dma(&rirb, 128, capabilities.dma_address_bits)?;
        if corb.len() < 1024 || rirb.len() < 2048 {
            return Err(Error::InvalidBuffer);
        }
        let mut controller = Self {
            registers,
            timer,
            config,
            capabilities,
            codec_mask: 0,
            token: ControllerToken {
                owner: corb.physical(),
                generation: 1,
            },
            lifecycle_failed: false,
            discovery_ready: false,
            extended,
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
            codec_controls: Vec::new(),
            conexant_codecs: Vec::new(),
            sigmatel_codecs: Vec::new(),
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

    pub(super) fn check_dma(buffer: &DmaBuffer, align: u64, address_bits: u8) -> Result<(), Error> {
        check_dma_range(buffer.physical(), buffer.len(), align, address_bits)
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
        self.refresh_extended()?;
        self.registers.write32(INTCTL, 0);
        self.registers.write16(WAKEEN, 0);
        for index in 0..self.streams.len() as u8 {
            self.stop_descriptor(index)?;
        }
        self.stop_commands()?;
        self.registers.write32(DPLBASE, 0);
        self.registers.write32(DPUBASE, 0);
        if self.config.reset_policy == ResetPolicy::Generic {
            return self.initialize_link();
        }
        // A failed disable can have partially changed PCI state; always attempt
        // the matching enable before returning, even when reset never began.
        if let Err(error) = self.registers.reset_clock_gate(false) {
            let _ = self.registers.reset_clock_gate(true);
            return Err(error);
        }
        let reset = self.initialize_link();
        let cleanup = self.registers.reset_clock_gate(true);
        cleanup?;
        reset?;
        self.refresh_extended()?;
        self.configure_extended_link()
    }

    fn initialize_link(&mut self) -> Result<(), Error> {
        let gctl = self.registers.read32(GCTL);
        if gctl == u32::MAX {
            return Err(Error::RegisterUnavailable { offset: GCTL });
        }
        if gctl & GCTL_RESET != 0 {
            self.registers.write16(STATESTS, CODEC_MASK);
        }
        let gctl = gctl & !(GCTL_RESET | GCTL_UNSOL);
        self.registers.write32(GCTL, gctl);
        self.wait(Phase::LinkResetEnter, |r| {
            let value = r.read32(GCTL);
            value != u32::MAX && value & GCTL_RESET == 0
        })?;
        self.delay(500); // Linux: >=100us link/codec PLL reset assertion.
        self.registers.write32(GCTL, gctl | GCTL_RESET);
        self.wait(Phase::LinkResetExit, |r| {
            let value = r.read32(GCTL);
            value != u32::MAX && value & GCTL_RESET != 0
        })?;
        self.delay(1000); // Codec initialization requires >=540us after CRST.
        let state = self.registers.read16(STATESTS);
        if state == u16::MAX {
            return Err(Error::RegisterUnavailable { offset: STATESTS });
        }
        self.codec_mask = state & CODEC_MASK;
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
                    let value = r.read16(CORBRP);
                    value != u16::MAX && value & POINTER_RESET != 0
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
        // Local response/overrun events feed the polled status and response
        // counter handshake. INTCTL stays zero, so these local enables cannot
        // request CPU interrupts. Start RIRB before CORB can produce a reply.
        self.registers.write8(RIRBCTL, RIRB_RUN_STATUS);
        self.registers.write8(CORBCTL, COMMAND_RUN);
        self.wait(Phase::CommandStart, |r| {
            let corb = r.read8(CORBCTL);
            let rirb = r.read8(RIRBCTL);
            corb != u8::MAX
                && rirb != u8::MAX
                && corb & COMMAND_RUN != 0
                && rirb & RIRB_RUN_STATUS == RIRB_RUN_STATUS
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
        if self.lifecycle_failed {
            return Err(Error::NeedsReset);
        }
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
        // Only this invocation's actual RUN readbacks may establish quiescence.
        // A prior stopped state can survive a failed reset/restart attempt.
        self.stopped = false;
        if let Err(error) = self.refresh_extended() {
            self.lifecycle_failed = true;
            self.command_poisoned = true;
            for stream in self.streams.iter_mut().flatten() {
                stream.poisoned = true;
            }
            return Err(error);
        }
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
        // Vendor amplifier effects follow actual stream-stop acknowledgements,
        // before command engines retire. A codec-control failure still permits
        // command-DMA quiescence, but is returned as a real incomplete shutdown.
        let codec_error = if error.is_none() {
            let mut error = self.shutdown_conexant_codecs().err();
            if let Err(fault) = self.shutdown_sigmatel_codecs() {
                error.get_or_insert(fault);
            }
            error
        } else {
            None
        };
        if let Err(fault) = self.stop_commands() {
            error.get_or_insert(fault);
        }
        self.command_poisoned = true;
        if let Some(error) = error {
            self.lifecycle_failed = true;
            return Err(error);
        }
        self.registers.write32(DPLBASE, 0);
        self.registers.write32(DPUBASE, 0);
        self.stopped = true;
        if let Some(error) = codec_error {
            self.lifecycle_failed = true;
            self.routing_failed = true;
            return Err(error);
        }
        Ok(())
    }
}

/// Check the entire device-visible extent, not merely its base. The caller has
/// already intersected actual identity/platform limits with GCAP's 32/64 flag.
fn check_dma_range(physical: u64, bytes: usize, align: u64, address_bits: u8) -> Result<(), Error> {
    let end = physical
        .checked_add(bytes as u64)
        .ok_or(Error::DmaAddress)?;
    if physical == 0
        || physical & (align - 1) != 0
        || (address_bits < 64 && end > 1u64 << address_bits)
    {
        return Err(Error::DmaAddress);
    }
    Ok(())
}

fn ring_size(capability: u8) -> Result<(u16, u8), Error> {
    if capability == u8::MAX {
        return Err(Error::UnsupportedRingSize);
    }
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
        bytes: Vec<u8>,
        link_controls: Vec<usize>,
        link_down_stuck: bool,
        link_up_stuck: bool,
        reject_link_clock: bool,
        link_clock_lost_on_power_up: bool,
        link_reads: BTreeMap<usize, usize>,
        clock: ModelClock,
        hardware_delay: u64,
        consume_delay: u64,
        response_delay: u64,
        next_consume: u64,
        events: Vec<Event>,
        replies: Vec<Reply>,
        self_clear: bool,
        reset_enter_stuck: bool,
        reset_gate: Option<Rc<Cell<bool>>>,
        link_initializations: u8,
        advertised_codecs: u16,
        codec_ready_after_resets: u8,
        drop_reply_until_resets: u8,
        codec_vendor_overrides: BTreeMap<u8, u32>,
        reset_exit_stuck: bool,
        command_stop_stuck: bool,
        corb_reset_stuck: bool,
        stream_start_stuck: bool,
        stream_stop_stuck: bool,
        stream_reset_stuck: bool,
        drop_reply: bool,
        drop_reply_command: Option<u32>,
        wrong_codec: bool,
        inject_unsolicited: bool,
        duplicate_reply: bool,
        rirb_reset_stuck: bool,
        response_backpressure: bool,
        response_count: u16,
        command_start_read_failure: Option<usize>,
        command_started_once: bool,
        control_read_failure: Option<(usize, usize)>,
        control_failure_after_write: Option<(usize, u32, usize)>,
        control_failure_active: bool,
        control_failed_reads: usize,
        binding_read_failure: bool,
        commands: Vec<u32>,
        command_times: Vec<(u32, u64)>,
        constant_reply: Option<u32>,
        parameters: BTreeMap<(u8, u8), u32>,
        pin_defaults: BTreeMap<u8, u32>,
        pin_senses: BTreeMap<u8, u32>,
        conexant_headset_model: bool,
        conexant_detection_ready: Option<u64>,
        conexant_detection_reads: usize,
        conexant_type: u32,
        conexant_vendor_fault: Option<u16>,
        conexant_trim: Option<u16>,
        conexant_mic_writes: usize,
        conexant_mic_fault_after: Option<usize>,
        sense_triggers: Vec<u8>,
        coefficient_indexes: BTreeMap<u8, u16>,
        coefficients: BTreeMap<(u8, u16), u16>,
        coefficient_read_fault: Option<u32>,
        coefficient_fault_after_write: bool,
        coefficient_fault_node: Option<u8>,
        coefficient_fault_write_threshold: usize,
        coefficient_write_nodes: BTreeMap<u8, usize>,
        coefficient_events: Vec<(u8, u16, u16, u64)>,
        depop_started_at: Option<u64>,
        depop_delay_us: Option<u64>,
        depop_mutate_saved: bool,
        coefficient_index_failed: bool,
        coefficient_index_reply: Option<(u8, u32)>,
        reject_coefficient_write: bool,
        reject_coefficient_node: Option<u8>,
        coefficient_writes: usize,
        connection_words: BTreeMap<(u8, u8), u32>,
        formats: BTreeMap<u8, u16>,
        bindings: BTreeMap<u8, u8>,
        route_controls: BTreeMap<(u8, u16), u8>,
        amplifiers: BTreeMap<(u8, bool, u8, u8), u8>,
        outputs_without_hardware_mute: Vec<u8>,
        power_ready: BTreeMap<u8, u64>,
        power_delay: u64,
        power_stuck: bool,
        power_error: bool,
        reject_route_control: Option<u16>,
        reject_route_after_write: bool,
        route_control_writes: BTreeMap<(u8, u16), usize>,
        reject_route_node: Option<u8>,
        reject_amplifier: bool,
        last_dma_time: u64,
        dma_step_bytes: usize,
        playback: Vec<u8>,
        capture_counter: u8,
        stream_descriptors_seen: usize,
        reads: usize,
        writes: Vec<(usize, u32, usize)>,
    }

    impl Model {
        fn new(entries: u16) -> Rc<RefCell<Self>> {
            let clock = ModelClock(Rc::new(Cell::new(0)));
            let mut model = Self {
                bytes: vec![0; 0x440],
                link_controls: Vec::new(),
                link_down_stuck: false,
                link_up_stuck: false,
                reject_link_clock: false,
                link_clock_lost_on_power_up: false,
                link_reads: BTreeMap::new(),
                clock,
                hardware_delay: 2,
                consume_delay: 2,
                response_delay: 3,
                next_consume: 0,
                events: Vec::new(),
                replies: Vec::new(),
                self_clear: false,
                reset_enter_stuck: false,
                reset_gate: None,
                link_initializations: 0,
                advertised_codecs: 1,
                codec_ready_after_resets: 0,
                drop_reply_until_resets: 0,
                codec_vendor_overrides: BTreeMap::new(),
                reset_exit_stuck: false,
                command_stop_stuck: false,
                corb_reset_stuck: false,
                stream_start_stuck: false,
                stream_stop_stuck: false,
                stream_reset_stuck: false,
                drop_reply: false,
                drop_reply_command: None,
                wrong_codec: false,
                inject_unsolicited: false,
                duplicate_reply: false,
                rirb_reset_stuck: false,
                response_backpressure: false,
                response_count: 0,
                command_start_read_failure: None,
                command_started_once: false,
                control_read_failure: None,
                control_failure_after_write: None,
                control_failure_active: false,
                control_failed_reads: 0,
                binding_read_failure: false,
                commands: Vec::new(),
                command_times: Vec::new(),
                constant_reply: Some(0x1234_abcd),
                parameters: BTreeMap::new(),
                pin_defaults: BTreeMap::new(),
                pin_senses: BTreeMap::new(),
                conexant_headset_model: false,
                conexant_detection_ready: None,
                conexant_detection_reads: 0,
                conexant_type: 0,
                conexant_vendor_fault: None,
                conexant_trim: None,
                conexant_mic_writes: 0,
                conexant_mic_fault_after: None,
                sense_triggers: Vec::new(),
                coefficient_indexes: BTreeMap::new(),
                coefficients: BTreeMap::new(),
                coefficient_read_fault: None,
                coefficient_fault_after_write: false,
                coefficient_fault_node: None,
                coefficient_fault_write_threshold: 1,
                coefficient_write_nodes: BTreeMap::new(),
                coefficient_events: Vec::new(),
                depop_started_at: None,
                depop_delay_us: Some(0),
                depop_mutate_saved: false,
                coefficient_index_failed: false,
                coefficient_index_reply: None,
                reject_coefficient_write: false,
                reject_coefficient_node: None,
                coefficient_writes: 0,
                connection_words: BTreeMap::new(),
                formats: BTreeMap::new(),
                bindings: BTreeMap::new(),
                route_controls: BTreeMap::new(),
                amplifiers: BTreeMap::new(),
                outputs_without_hardware_mute: Vec::new(),
                power_ready: BTreeMap::new(),
                power_delay: 12,
                power_stuck: false,
                power_error: false,
                reject_route_control: None,
                reject_route_after_write: false,
                route_control_writes: BTreeMap::new(),
                reject_route_node: None,
                reject_amplifier: false,
                last_dma_time: 0,
                dma_step_bytes: 0,
                playback: Vec::new(),
                capture_counter: 0,
                stream_descriptors_seen: 0,
                reads: 0,
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
                let event_value = if self.link_controls.contains(&event.offset) {
                    (self.get(event.offset, 4) & !(1 << 23)) | (event.value & (1 << 23))
                } else {
                    event.value
                };
                self.set(event.offset, event_value, event.bytes);
                if event.offset == GCTL && event.value & GCTL_RESET == 0 {
                    self.replies.clear(); // Link reset discards in-flight codec responses.
                }
                if event.offset == GCTL && event.value & GCTL_RESET != 0 && was_reset {
                    self.link_initializations += 1;
                    self.set(STATESTS, u32::from(self.advertised_codecs), 2);
                }
            }
            let response_limit = match self.get(RINTCNT, 2) as u16 {
                0 => 256,
                value => value,
            };
            if self.bytes[CORBCTL] & COMMAND_RUN != 0
                && now >= self.next_consume
                && (!self.response_backpressure || self.response_count < response_limit)
            {
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
                    self.command_times.push((command, now));
                    self.set(CORBRP, u32::from(next), 2);
                    self.next_consume = now + self.consume_delay;
                    let response = self.reply_for(command);
                    if !self.drop_reply
                        && self.drop_reply_command != Some(command)
                        && self.link_initializations >= self.drop_reply_until_resets
                    {
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
            self.response_count += 1;
            if self.bytes[RIRBCTL] & RIRB_RESPONSE_ENABLE != 0 {
                self.bytes[RIRBSTS] |= RIRB_RESPONSE;
            }
        }

        fn reply_for(&mut self, command: u32) -> u32 {
            if command & 0x0fff_ffff == 0x000f_0000 {
                if self.link_initializations < self.codec_ready_after_resets {
                    return 0;
                }
                if let Some(value) = self.codec_vendor_overrides.get(&((command >> 28) as u8)) {
                    return *value;
                }
            }
            if let Some(value) = self.constant_reply {
                return value;
            }
            let node = ((command >> 20) & 127) as u8;
            let verb = ((command >> 8) & 0xfff) as u16;
            let long = (command >> 16) & 15;
            if self.conexant_headset_model && node == 0x1c {
                if self.conexant_vendor_fault == Some(verb) {
                    return u32::MAX;
                }
                if command & 0x000f_ffff == 0x0003_be10 {
                    self.conexant_trim = Some(0x0e10);
                    return 0;
                }
                if verb == 0xca0 {
                    self.conexant_detection_reads += 1;
                    return if self
                        .conexant_detection_ready
                        .is_some_and(|time| self.clock.now_us() >= time)
                    {
                        0x80
                    } else {
                        0
                    };
                }
                if verb == 0xcb0 {
                    return self.conexant_type;
                }
            }

            if long == 3 {
                let value = command as u16;
                let output = value & (1 << 15) != 0;
                assert_eq!(value & (1 << 14) != 0, !output);
                let index = ((value >> 8) & 15) as u8;
                let gain = if output && self.outputs_without_hardware_mute.contains(&node) {
                    value as u8 & 0x7f
                } else {
                    value as u8
                };
                if value & (1 << 13) != 0 {
                    self.amplifiers.insert((node, output, index, 0), gain);
                }
                if value & (1 << 12) != 0 {
                    self.amplifiers.insert((node, output, index, 1), gain);
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
            match long {
                5 => {
                    self.coefficient_indexes.insert(node, command as u16);
                    return 0;
                }
                13 => {
                    if let Some((target, value)) = self.coefficient_index_reply
                        && target == node
                    {
                        return value;
                    }
                    return if self.coefficient_index_failed {
                        u32::MAX
                    } else {
                        u32::from(*self.coefficient_indexes.get(&node).unwrap_or(&0))
                    };
                }
                4 => {
                    self.coefficient_writes += 1;
                    *self.coefficient_write_nodes.entry(node).or_default() += 1;
                    self.coefficient_events.push((
                        node,
                        *self.coefficient_indexes.get(&node).unwrap_or(&0),
                        command as u16,
                        self.clock.now_us(),
                    ));
                    if !self.reject_coefficient_write && self.reject_coefficient_node != Some(node)
                    {
                        self.coefficients.insert(
                            (node, *self.coefficient_indexes.get(&node).unwrap_or(&0)),
                            command as u16,
                        );
                        if node == 0x58
                            && self.coefficient_indexes.get(&node) == Some(&0)
                            && command as u16 == 0xf888
                        {
                            self.depop_started_at = Some(self.clock.now_us());
                        }
                    }
                    return 0;
                }
                12 => {
                    if let Some(value) = self.coefficient_read_fault
                        && self
                            .coefficient_fault_node
                            .is_none_or(|target| target == node)
                        && (!self.coefficient_fault_after_write
                            || if let Some(target) = self.coefficient_fault_node {
                                self.coefficient_write_nodes
                                    .get(&target)
                                    .copied()
                                    .unwrap_or(0)
                                    >= self.coefficient_fault_write_threshold
                            } else {
                                self.coefficient_writes >= self.coefficient_fault_write_threshold
                            })
                    {
                        return value;
                    }
                    if node == 0x58
                        && self.coefficient_indexes.get(&node) == Some(&0)
                        && let Some(start) = self.depop_started_at
                        && let Some(delay) = self.depop_delay_us
                        && self.clock.now_us().saturating_sub(start) >= delay
                    {
                        self.depop_started_at = None;
                        *self.coefficients.entry((0x58, 0)).or_default() &= !0x8000;
                        if self.depop_mutate_saved {
                            for (index, mask) in [(0x38, 0x100), (0x0d, 2), (0x36, 0x200)] {
                                *self.coefficients.entry((0x20, index)).or_default() &= !mask;
                            }
                        }
                    }
                    return u32::from(
                        *self
                            .coefficients
                            .get(&(node, *self.coefficient_indexes.get(&node).unwrap_or(&0)))
                            .unwrap_or(&0),
                    );
                }
                _ => (),
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
                0x701 | 0x707 | 0x70c | 0x715 | 0x716 | 0x717 | 0x7e7 => {
                    *self
                        .route_control_writes
                        .entry((node, verb + 0x800))
                        .or_default() += 1;
                    if self.conexant_headset_model && node == 0x19 && verb == 0x707 {
                        self.conexant_mic_writes += 1;
                    }
                    self.route_controls
                        .insert((node, verb + 0x800), command as u8);
                    0
                }
                0xf01 | 0xf07 | 0xf0c | 0xf15 | 0xf16 | 0xf17 => {
                    if self.conexant_headset_model
                        && node == 0x19
                        && verb == 0xf07
                        && self
                            .conexant_mic_fault_after
                            .is_some_and(|count| self.conexant_mic_writes >= count)
                    {
                        return u32::MAX;
                    }
                    if self.reject_route_control == Some(verb)
                        && self.reject_route_node.is_none_or(|target| target == node)
                        && (!self.reject_route_after_write
                            || self
                                .route_control_writes
                                .get(&(node, verb))
                                .is_some_and(|count| *count > 0))
                    {
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
                0xf1c => *self.pin_defaults.get(&node).unwrap_or(&0x0101_4010),
                0xf09 => *self.pin_senses.get(&node).unwrap_or(&0),
                0xf20 => 0x1043_8693,
                0x709 => {
                    self.sense_triggers.push(node);
                    0
                }
                0x706 => {
                    self.bindings.insert(node, command as u8);
                    0
                }
                0xf06 => {
                    if self.binding_read_failure {
                        u32::MAX
                    } else {
                        u32::from(*self.bindings.get(&node).unwrap_or(&0))
                    }
                }
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
            if self.control_failure_after_write == Some((offset, value, bytes)) {
                self.control_failure_active = true;
            }
            if offset == STATESTS
                || offset == CORBSTS
                || offset == RIRBSTS
                || (offset >= 0x80 && (offset - 0x80) % 0x20 == SD_STS)
            {
                let old = self.get(offset, bytes);
                if offset == RIRBSTS && old & value & u32::from(RIRB_RESPONSE) != 0 {
                    self.response_count = 0;
                }
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
            if self.link_controls.contains(&offset) {
                assert_eq!(bytes, 4);
                let old = self.get(offset, 4);
                let mut stored = (value & !(1 << 23)) | (old & (1 << 23));
                if value & 15 != old & 15 {
                    assert_eq!(
                        old & ((1 << 16) | (1 << 23)),
                        0,
                        "SCF changed before link acknowledged off"
                    );
                    if self.reject_link_clock {
                        stored = (stored & !15) | (old & 15);
                    }
                }
                if value & (1 << 16) != 0 && self.link_clock_lost_on_power_up {
                    stored &= !15;
                }
                self.set(offset, stored, 4);
                if !(value & (1 << 16) == 0 && self.link_down_stuck
                    || value & (1 << 16) != 0 && self.link_up_stuck)
                {
                    self.events.push(Event {
                        due: self.clock.now_us() + self.hardware_delay,
                        offset,
                        value: if value & (1 << 16) != 0 {
                            stored | (1 << 23)
                        } else {
                            stored & !(1 << 23)
                        },
                        bytes: 4,
                    });
                }
                return;
            }
            if offset == GCTL {
                if let Some(gate) = &self.reset_gate {
                    assert!(
                        !gate.get(),
                        "GCTL written while mandatory PCI clock gating remained enabled"
                    );
                }
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
            if offset == CORBCTL
                && value & u32::from(COMMAND_RUN) != 0
                && self.bytes[RIRBCTL] & COMMAND_RUN != 0
            {
                self.command_started_once = true;
            }
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
        fn region_bytes(&self) -> usize {
            self.0.borrow().bytes.len()
        }
        fn read8(&mut self, offset: usize) -> u8 {
            let mut m = self.0.borrow_mut();
            m.reads += 1;
            m.advance();
            if (m.command_started_once && m.command_start_read_failure == Some(offset))
                || (m.control_failure_active && m.control_read_failure == Some((offset, 1)))
            {
                return u8::MAX;
            }
            m.get(offset, 1) as u8
        }
        fn read16(&mut self, offset: usize) -> u16 {
            let mut m = self.0.borrow_mut();
            m.reads += 1;
            m.advance();
            if m.control_failure_active && m.control_read_failure == Some((offset, 2)) {
                return u16::MAX;
            }
            m.get(offset, 2) as u16
        }
        fn read32(&mut self, offset: usize) -> u32 {
            let mut m = self.0.borrow_mut();
            if m.link_controls.contains(&offset) {
                *m.link_reads.entry(offset).or_default() += 1;
            }
            m.reads += 1;
            m.advance();
            if m.control_failure_active && m.control_read_failure == Some((offset, 4)) {
                m.control_failed_reads += 1;
                return u32::MAX;
            }
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

    struct ResetPciState {
        words: [u32; 64],
        writes: Vec<(u32, u64, u8, bool)>,
        reject_disable: bool,
        reject_enable: bool,
        failed_read: u8,
        reads: usize,
        clock_reads: usize,
    }
    impl Default for ResetPciState {
        fn default() -> Self {
            Self {
                words: [0; 64],
                writes: Vec::new(),
                reject_disable: false,
                reject_enable: false,
                failed_read: 0,
                reads: 0,
                clock_reads: 0,
            }
        }
    }
    struct ResetPci {
        model: Rc<RefCell<Model>>,
        gate: Rc<Cell<bool>>,
        state: Rc<RefCell<ResetPciState>>,
        clock: ModelClock,
    }
    impl crate::bus::pci::ConfigSpace for ResetPci {
        fn read32(&self, offset: u16) -> u32 {
            let mut s = self.state.borrow_mut();
            s.reads += 1;
            if offset == 0x48 {
                s.clock_reads += 1;
            }
            if offset == 0x48
                && (s.failed_read == 1
                    || (s.failed_read == 2 && s.writes.iter().any(|(v, ..)| v & 0x40 == 0))
                    || (s.failed_read == 3 && s.writes.iter().any(|(v, ..)| v & 0x40 != 0)))
            {
                return u32::MAX;
            }
            s.words[usize::from(offset / 4)]
        }
        fn write32(&mut self, offset: u16, value: u32) {
            assert_eq!(offset, 0x48);
            let mut s = self.state.borrow_mut();
            let model = self.model.borrow();
            s.writes.push((
                value,
                self.clock.now_us(),
                model.link_initializations,
                model.get(CORBCTL, 1) & u32::from(COMMAND_RUN) != 0,
            ));
            if (value & 0x40 == 0 && s.reject_disable) || (value & 0x40 != 0 && s.reject_enable) {
                return;
            }
            s.words[usize::from(offset / 4)] = value;
            self.gate.set(value & 0x40 != 0);
        }
    }
    fn reset_pci(
        model: &Rc<RefCell<Model>>,
    ) -> (
        crate::bus::pci::Function<ResetPci>,
        Rc<RefCell<ResetPciState>>,
    ) {
        let mut state = ResetPciState::default();
        state.words[0] = 0xa170_8086;
        state.words[2] = 0x0403_0000;
        state.words[4] = 0xfebf_0000;
        state.words[18] = 0xa5a5_00c3;
        let state = Rc::new(RefCell::new(state));
        let gate = Rc::new(Cell::new(true));
        model.borrow_mut().reset_gate = Some(gate.clone());
        let function = crate::bus::pci::Function::new(
            crate::bus::pci::Address {
                segment: 0,
                bus: 0,
                device: 27,
                function: 0,
            },
            ResetPci {
                model: model.clone(),
                gate,
                state: state.clone(),
                clock: model.borrow().clock.clone(),
            },
        )
        .unwrap();
        (function, state)
    }
    fn extended_model() -> Rc<RefCell<Model>> {
        with_extended(graph_model())
    }
    fn with_extended(model: Rc<RefCell<Model>>) -> Rc<RefCell<Model>> {
        {
            let mut m = model.borrow_mut();
            m.bytes.resize(0x2000, 0);
            m.set(0x14, 0x500, 2);
            for (offset, value) in [
                (0x500, 0x1001_0800), //GTS ->PP, one known global counter unit.
                (0x800, 0x1003_0c00), //PP ->ML.
                (0xc00, 0x1002_0700), //ML ->SPB.
                (0xc04, 1),           //Two conventional HDA links.
                (0xc40, 0x3f),
                (0xc44, (1 << 16) | (1 << 23)), //First link6MHz.
                (0xc80, 0x3f),
                (0xc84, 3 | (1 << 16) | (1 << 23)), //Second48MHz untouched.
                (0x700, 0x1004_1000),               //SPB ->DRSM.
                (0x1000, 0x1005_0000),
            ] {
                m.set(offset, value, 4);
            }
            m.link_controls = vec![0xc44, 0xc84];
        }
        model
    }

    fn modern_config() -> Config {
        Config {
            reset_policy: ResetPolicy::IntelClockGate,
            stream_tag_policy: StreamTagPolicy::PerDirection,
            ..config()
        }
    }

    #[test]
    fn mandatory_pci_reset_policy_and_exact_prepared_bdf_refuse_bypasses_before_dma_or_mmio() {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let remaining = fixture.allocator.remaining();
        assert!(matches!(
            create(&model, &mut fixture, modern_config()),
            Err(Error::InvalidConfiguration)
        ));
        assert_eq!(access_counts(&model), (0, 0, 0));
        assert_eq!(fixture.allocator.remaining(), remaining);
        let (mut function, state) = reset_pci(&model);
        let prepared = pci::tests::modern_prepared_model(function.address);
        assert!(matches!(
            unsafe { prepared.claim_mmio() },
            Err(Error::InvalidConfiguration)
        ));
        let prepared = pci::tests::modern_prepared_model(function.address);
        function.address.device = 28;
        assert!(matches!(
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) },
            Err(pci::AttachError::IdentityChanged)
        ));
        function.address.device = 27;
        let prepared = pci::tests::modern_prepared_model(function.address);
        let registers =
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                .unwrap();
        let pci_reads = state.borrow().reads;
        let timer = model.borrow().clock.clone();
        assert!(matches!(
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, config()) },
            Err(Error::InvalidConfiguration)
        ));
        assert_eq!(state.borrow().reads, pci_reads);
        assert_eq!(access_counts(&model), (0, 0, 0));
        assert_eq!(fixture.allocator.remaining(), remaining);
    }

    #[test]
    fn native_pci_clock_bracket_covers_initial_reset_reinitialize_and_discovery_retry() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        let (mut function, state) = reset_pci(&model);
        let prepared = pci::tests::modern_prepared_model(function.address);
        let registers =
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                .unwrap();
        let timer = model.borrow().clock.clone();
        // Once is the profile minimum; an explicit caller may elect bounded
        // discovery retries without weakening any mandatory controller policy.
        let selected = Config {
            probe_policy: ProbePolicy::Retry {
                attempts: 2,
                delay_us: 80,
            },
            ..modern_config()
        };
        let mut controller =
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, selected) }.unwrap();
        controller.reinitialize().unwrap();
        model.borrow_mut().codec_ready_after_resets = 3;
        let result = controller.discover_codecs().unwrap();
        assert_eq!(result.attempts, 2);
        let pci = state.borrow();
        assert_eq!(pci.writes.len(), 6);
        for pair in pci.writes.as_chunks::<2>().0 {
            assert_eq!(pair[0].0, 0xa5a5_0083);
            assert_eq!(pair[1].0, 0xa5a5_00c3);
            assert!(pair[1].1 > pair[0].1);
            assert_eq!(pair[1].2, pair[0].2 + 1);
            assert!(!pair[0].3);
            assert!(pair[1].3);
            assert!(
                model
                    .borrow()
                    .writes
                    .iter()
                    .any(|(offset, value, width)| *offset == GCTL
                        && *width == 4
                        && *value & GCTL_RESET == 0)
            );
        }
    }

    #[test]
    fn failed_native_pci_reset_controls_never_report_constructor_success_and_attempt_matching_cleanup()
     {
        for fault in 0..5 {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let (mut function, state) = reset_pci(&model);
            match fault {
                0 => state.borrow_mut().reject_disable = true,
                1 => state.borrow_mut().reject_enable = true,
                2 => state.borrow_mut().failed_read = 1,
                3 => state.borrow_mut().failed_read = 2,
                _ => state.borrow_mut().failed_read = 3,
            }
            let prepared = pci::tests::modern_prepared_model(function.address);
            let registers =
                unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                    .unwrap();
            let timer = model.borrow().clock.clone();
            assert!(matches!(
                unsafe {
                    Controller::new(registers, timer, &mut fixture.allocator, modern_config())
                },
                Err(Error::PciResetControl { offset: 0x48 })
            ));
            assert!(model.borrow().commands.is_empty());
            assert_eq!(model.borrow().get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
            assert_eq!(model.borrow().get(RIRBCTL, 1) & u32::from(COMMAND_RUN), 0);
            if fault == 2 {
                assert!(state.borrow().clock_reads >= 2);
            }
            if fault == 3 {
                assert!(state.borrow().clock_reads >= 3);
            }
            if fault == 0 || fault == 1 || fault == 4 {
                let writes = &state.borrow().writes;
                assert_eq!(writes.len(), 2);
                assert_eq!(writes[0].0 & 0x40, 0);
                assert_ne!(writes[1].0 & 0x40, 0);
            }
        }
    }

    #[test]
    fn failed_native_reset_and_quiescence_retain_dma_block_operations_and_allow_explicit_recovery()
    {
        for fault in 0..3 {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            let (mut function, state) = reset_pci(&model);
            let prepared = pci::tests::modern_prepared_model(function.address);
            let registers =
                unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                    .unwrap();
            let timer = model.borrow().clock.clone();
            let mut controller = unsafe {
                Controller::new(registers, timer, &mut fixture.allocator, modern_config())
            }
            .unwrap();
            let id = controller
                .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
                .unwrap();
            controller.start(id).unwrap();
            let remaining = fixture.allocator.remaining();
            match fault {
                0 => model.borrow_mut().stream_stop_stuck = true,
                1 => model.borrow_mut().reset_exit_stuck = true,
                _ => state.borrow_mut().reject_enable = true,
            }
            let error = controller.reinitialize().unwrap_err();
            if fault == 0 {
                assert_eq!(error, Error::Timeout(Phase::StreamStop));
                assert_eq!(state.borrow().writes.len(), 2);
                assert!(controller.streams[usize::from(id.descriptor_index())].is_some());
            } else {
                assert_eq!(
                    error,
                    if fault == 1 {
                        Error::Timeout(Phase::LinkResetExit)
                    } else {
                        Error::PciResetControl { offset: 0x48 }
                    }
                );
                let writes = &state.borrow().writes;
                assert_eq!(writes.len(), 4);
                assert_eq!(writes[2].0 & 0x40, 0);
                assert_ne!(writes[3].0 & 0x40, 0);
            }
            assert_eq!(fixture.allocator.remaining(), remaining);
            let before = access_counts(&model);
            assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
            assert_eq!(
                controller.start(id),
                Err(if fault == 0 {
                    Error::NeedsReset
                } else {
                    Error::InvalidStream
                })
            );
            assert_eq!(
                controller.allocate_stream(
                    Direction::Capture,
                    pcm(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
            state.borrow_mut().reject_enable = false;
            model.borrow_mut().reset_exit_stuck = false;
            model.borrow_mut().stream_stop_stuck = false;
            controller.reinitialize().unwrap();
            controller.verb(verb()).unwrap();
        }
    }

    #[test]
    fn extended_link_prefers_supported_clocks_and_preserves_other_link_and_capability_state() {
        for (frequencies, expected) in [
            (0x3f, 2u8),
            (0x3b, 3),
            (0x33, 1),
            (0x31, 4),
            (0x21, 5),
            (1, 0),
        ] {
            for initially_on in [false, true] {
                let mut fixture = Fixture::new();
                let model = extended_model();
                model.borrow_mut().set(0xc40, frequencies, 4);
                model.borrow_mut().set(
                    0xc44,
                    if initially_on {
                        (1 << 16) | (1 << 23)
                    } else {
                        0
                    },
                    4,
                );
                let (mut function, state) = reset_pci(&model);
                let prepared = pci::tests::modern_prepared_model(function.address);
                let registers = unsafe {
                    prepared.bind_registers(&mut function, ModelRegisters(model.clone()))
                }
                .unwrap();
                let timer = model.borrow().clock.clone();
                let mut controller = unsafe {
                    Controller::new(registers, timer, &mut fixture.allocator, modern_config())
                }
                .unwrap();
                assert_eq!(
                    controller.link_clock(),
                    Ok(Some(LinkClock {
                        encoding: expected,
                        mhz: 6u16 << expected
                    }))
                );
                assert_eq!(model.borrow().get(0xc44, 4) & 15, u32::from(expected));
                assert_eq!(
                    model.borrow().get(0xc44, 4) & ((1 << 16) | (1 << 23)),
                    (1 << 16) | (1 << 23)
                );
                assert_eq!(model.borrow().get(0xc84, 4), 3 | (1 << 16) | (1 << 23));
                assert!(
                    !model
                        .borrow()
                        .writes
                        .iter()
                        .any(|(offset, _, _)| matches!(*offset, 0xc84 | 0x804 | 0x704 | 0x1004))
                );
                assert_eq!(state.borrow().writes.len(), 2);
                controller.reinitialize().unwrap();
                assert_eq!(controller.link_clock().unwrap().unwrap().encoding, expected);
                controller.verb(verb()).unwrap();
            }
        }
    }

    #[test]
    fn extended_preflight_refuses_active_processing_malformed_bodies_and_unmapped_caps_before_dma_or_writes()
     {
        for variant in 0..17 {
            let mut fixture = Fixture::new();
            let model = extended_model();
            match variant {
                0 => model.borrow_mut().set(0x804, 1 << 30, 4),
                1 => model.borrow_mut().set(0x804, 1, 4),
                2 => model.borrow_mut().set(0x704, 1, 4),
                3 => model.borrow_mut().set(0x1004, 1, 4),
                4 => model.borrow_mut().set(0x14, 0x501, 2),
                5 => model.borrow_mut().set(0x14, 0x40, 2),
                6 => model.borrow_mut().set(0x1000, 0x1005_5000, 4),
                7 => model.borrow_mut().set(0x1000, 0x1005_0804, 4), //Back edge into PP body.
                8 => model.borrow_mut().set(0xc04, u32::MAX, 4),
                9 => model.borrow_mut().set(0xc40, (1 << 28) | 0x3f, 4),
                10 => model.borrow_mut().set(0xc40, 0, 4),
                11 => model.borrow_mut().set(0x500, 0x1006_0800, 4),
                12 => model.borrow_mut().set(0x500, 0x2001_0800, 4),
                13 => model.borrow_mut().set(0x804, u32::MAX, 4),
                14 => model.borrow_mut().set(0x1000, 0x1005_0700, 4), //Repeated SPB.
                15 => model.borrow_mut().bytes.truncate(0xc60),
                _ => model.borrow_mut().set(0x504, 1, 4), //Undecoded GTS geometry.
            }
            let (mut function, state) = reset_pci(&model);
            let prepared = pci::tests::modern_prepared_model(function.address);
            let registers =
                unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                    .unwrap();
            let timer = model.borrow().clock.clone();
            let remaining = fixture.allocator.remaining();
            assert!(
                unsafe {
                    Controller::new(registers, timer, &mut fixture.allocator, modern_config())
                }
                .is_err(),
                "variant {variant}"
            );
            assert_eq!(
                fixture.allocator.remaining(),
                remaining,
                "variant {variant}"
            );
            assert!(model.borrow().writes.is_empty(), "variant {variant}");
            assert!(state.borrow().writes.is_empty(), "variant {variant}");
        }
    }

    #[test]
    fn extended_link_power_clock_and_failed_reads_refuse_constructor_and_attempt_link_restore() {
        for variant in 0..9 {
            let mut fixture = Fixture::new();
            let model = extended_model();
            match variant {
                0 => model.borrow_mut().link_down_stuck = true,
                1 => model.borrow_mut().link_up_stuck = true,
                2 => model.borrow_mut().reject_link_clock = true,
                3 => model.borrow_mut().set(0xc44, 1 << 16, 4),
                4 => model.borrow_mut().set(0xc44, 7 | (1 << 16) | (1 << 23), 4),
                5 => {
                    let mut m = model.borrow_mut();
                    m.control_failure_after_write = Some((0xc44, 2, 4));
                    m.control_read_failure = Some((0xc44, 4));
                }
                6 => model.borrow_mut().link_clock_lost_on_power_up = true,
                7 => {
                    let mut m = model.borrow_mut();
                    m.set(0xc40, 4, 4);
                    m.set(0xc44, 3 | (1 << 16) | (1 << 23), 4);
                }
                _ => {
                    let mut m = model.borrow_mut();
                    m.control_failure_after_write = Some((0xc44, 0x10002, 4));
                    m.control_read_failure = Some((0xc44, 4));
                }
            }
            let (mut function, _state) = reset_pci(&model);
            let prepared = pci::tests::modern_prepared_model(function.address);
            let registers =
                unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                    .unwrap();
            let timer = model.borrow().clock.clone();
            let result = unsafe {
                Controller::new(registers, timer, &mut fixture.allocator, modern_config())
            };
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("variant {variant} succeeded"),
            };
            assert_eq!(
                error,
                match variant {
                    0 => Error::Timeout(Phase::LinkPowerDown),
                    1 => Error::Timeout(Phase::LinkPowerUp),
                    2 | 6 => Error::LinkClockRejected { offset: 0xc44 },
                    3 => Error::LinkPowerUncertain { offset: 0xc44 },
                    4 | 7 => Error::UnsupportedLink { offset: 0xc44 },
                    _ => Error::RegisterUnavailable { offset: 0xc44 },
                }
            );
            assert!(model.borrow().commands.is_empty());
            assert_eq!(model.borrow().get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
            assert_eq!(model.borrow().get(RIRBCTL, 1) & u32::from(COMMAND_RUN), 0);
            if variant == 1 {
                assert!(
                    model
                        .borrow()
                        .writes
                        .iter()
                        .filter(|(offset, value, _)| *offset == 0xc44 && value & (1 << 16) != 0)
                        .count()
                        >= 2
                );
            }
            if variant == 5 || variant == 8 {
                assert!(model.borrow().control_failed_reads >= 2);
            }
            if variant == 0 || variant == 1 || variant == 2 {
                assert!(
                    model
                        .borrow()
                        .writes
                        .iter()
                        .any(|(offset, value, _)| *offset == 0xc44 && value & (1 << 16) != 0)
                );
            }
        }
    }

    #[test]
    fn processing_ownership_change_refuses_reset_and_shutdown_without_touching_active_dsp_or_retiring_dma()
     {
        let mut fixture = Fixture::new();
        let model = extended_model();
        let (mut function, state) = reset_pci(&model);
        let prepared = pci::tests::modern_prepared_model(function.address);
        let registers =
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                .unwrap();
        let timer = model.borrow().clock.clone();
        let mut controller =
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, modern_config()) }
                .unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller.start(id).unwrap();
        model.borrow_mut().set(0x804, 1 << 30, 4);
        let generation = controller.token;
        let writes = model.borrow().writes.len();
        let pci_writes = state.borrow().writes.len();
        assert_eq!(
            controller.reinitialize(),
            Err(Error::ProcessingOwned { offset: 0x804 })
        );
        assert_eq!(
            controller.shutdown(),
            Err(Error::ProcessingOwned { offset: 0x804 })
        );
        assert_eq!(model.borrow().writes.len(), writes);
        assert_eq!(state.borrow().writes.len(), pci_writes);
        assert_eq!(controller.token, generation);
        assert!(controller.streams[usize::from(id.descriptor_index())].is_some());
        assert_eq!(controller.link_clock(), Err(Error::NeedsReset));
        assert_eq!(controller.write_pcm(id, 0, &[1]), Err(Error::NeedsReset));
        assert_ne!(
            model
                .borrow()
                .get(stream_base(id.descriptor_index()) + SD_CTL, 1)
                & u32::from(SD_RUN),
            0
        );
    }

    #[test]
    fn configured_nonzero_link_clock_is_preserved_and_failed_reinitialization_never_exposes_stale_clock_metadata()
     {
        for initially_on in [false, true] {
            let mut fixture = Fixture::new();
            let model = extended_model();
            model.borrow_mut().set(
                0xc44,
                3 | if initially_on {
                    (1 << 16) | (1 << 23)
                } else {
                    0
                },
                4,
            );
            let (mut function, _state) = reset_pci(&model);
            let prepared = pci::tests::modern_prepared_model(function.address);
            let registers =
                unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                    .unwrap();
            let timer = model.borrow().clock.clone();
            let mut controller = unsafe {
                Controller::new(registers, timer, &mut fixture.allocator, modern_config())
            }
            .unwrap();
            assert_eq!(
                controller.link_clock(),
                Ok(Some(LinkClock {
                    encoding: 3,
                    mhz: 48
                }))
            );
            assert_eq!(
                model
                    .borrow()
                    .writes
                    .iter()
                    .filter(|(offset, _, _)| *offset == 0xc44)
                    .count(),
                usize::from(!initially_on)
            );
            let id = controller
                .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
                .unwrap();
            controller.start(id).unwrap();
            let remaining = fixture.allocator.remaining();
            model.borrow_mut().set(0xc44, (1 << 16) | (1 << 23), 4);
            model.borrow_mut().reject_link_clock = true;
            assert_eq!(
                controller.reinitialize(),
                Err(Error::LinkClockRejected { offset: 0xc44 })
            );
            assert_eq!(controller.link_clock(), Err(Error::NeedsReset));
            assert_eq!(controller.start(id), Err(Error::InvalidStream));
            assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
            assert_eq!(fixture.allocator.remaining(), remaining);
            model.borrow_mut().reject_link_clock = false;
            controller.reinitialize().unwrap();
            assert_eq!(
                controller.link_clock(),
                Ok(Some(LinkClock {
                    encoding: 2,
                    mhz: 24
                }))
            );
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
    fn actual_modern_pci_preparation_composes_reset_links_routes_and_finite_duplex_dma() {
        for device in [
            0xa170, 0x34c8, 0x3dc8, 0xa0c8, 0x43c8, 0x7ad0, 0x51c8, 0x51c9, 0x51cd, 0x51cc, 0x54c8,
            0x7e28,
        ] {
            let mut fixture = Fixture::new();
            let model = with_extended(analog_model());
            let gate = Rc::new(Cell::new(true));
            model.borrow_mut().reset_gate = Some(gate.clone());
            let (mut function, pci_timer, bar) = pci::tests::modern_pci_model_for(device);
            pci::tests::connect_reset_gate(&mut function, gate.clone());
            let registers = unsafe {
                pci::prepare_with_registers(
                    &mut function,
                    bar,
                    &pci_timer,
                    pci::Ownership::ExclusiveLegacy,
                    ModelRegisters(model.clone()),
                )
            }
            .unwrap();
            let selected = registers.config();
            let timer = model.borrow().clock.clone();
            let mut controller =
                unsafe { Controller::new(registers, timer, &mut fixture.allocator, selected) }
                    .unwrap();
            assert!(gate.get()); //The model asserts every CRST write occurs with gate clear.
            assert_eq!(controller.link_clock().unwrap().unwrap().mhz, 24);
            let graph = controller.enumerate_codec(0).unwrap();
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
            assert_eq!(playback.tag(), 1);
            assert_eq!(capture.tag(), 1);
            assert_ne!(playback, capture);
            let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            controller
                .configure_analog_route(
                    &graph,
                    &output,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None,
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
            controller.write_pcm(playback, 0, &[0x5a; 256]).unwrap();
            controller.fill_capture(capture, 0xa5).unwrap();
            controller.start(capture).unwrap();
            controller.start(playback).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 16);
            assert!(controller.status(playback).unwrap().period_completed);
            assert!(controller.status(capture).unwrap().period_completed);
            controller.stop(playback).unwrap();
            controller.stop(capture).unwrap();
            assert!(model.borrow().playback.len() >= 256);
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5a));
            let mut captured = [0; 256];
            controller.read_pcm(capture, 0, &mut captured).unwrap();
            assert_eq!(captured, core::array::from_fn(|index| index as u8));
            model.borrow_mut().dma_step_bytes = 0;
            controller.reinitialize().unwrap();
            assert_eq!(model.borrow().link_initializations, 2);
            assert!(gate.get());
            let before = access_counts(&model);
            assert_eq!(controller.start(playback), Err(Error::InvalidStream));
            assert_eq!(
                controller.read_pcm(capture, 0, &mut captured),
                Err(Error::InvalidStream)
            );
            assert_eq!(access_counts(&model), before);
            controller.shutdown().unwrap();
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

    fn retry_config(attempts: u8) -> Config {
        Config {
            probe_policy: ProbePolicy::Retry {
                attempts,
                delay_us: 80,
            },
            ..config()
        }
    }

    #[test]
    fn discovery_budget_and_required_pre_stream_gate_fail_before_any_register_access() {
        for (attempts, delay_us) in [(0, 1), (61, 1), (1, 0), (1, 1_000_001)] {
            let mut fixture = Fixture::new();
            let model = graph_model();
            assert!(matches!(
                create(
                    &model,
                    &mut fixture,
                    Config {
                        probe_policy: ProbePolicy::Retry { attempts, delay_us },
                        ..config()
                    }
                ),
                Err(Error::InvalidConfiguration)
            ));
            assert_eq!(access_counts(&model), (0, 0, 0));
        }
        let mut fixture = Fixture::new();
        let model = graph_model();
        let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
        // Manual enumeration does not bypass an identity-required discovery gate.
        controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        let remaining = fixture.allocator.remaining();
        assert_eq!(
            controller.allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator
            ),
            Err(Error::NeedsDiscovery)
        );
        assert_eq!(access_counts(&model), before);
        assert_eq!(fixture.allocator.remaining(), remaining);
        let result = controller.discover_codecs().unwrap();
        assert_eq!(result.attempts, 1);
        assert_eq!(result.codecs.len(), 1);
        assert!(result.failures.is_empty());
        controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let before = access_counts(&model);
        let failure = controller.discover_codecs().unwrap_err();
        assert_eq!(failure.attempts, 0);
        assert_eq!(failure.error, Error::StreamsAllocated);
        assert_eq!(access_counts(&model), before);
        controller.reinitialize().unwrap();
        assert_eq!(
            controller.allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator
            ),
            Err(Error::NeedsDiscovery)
        );
    }

    #[test]
    fn discovery_retries_reset_generation_and_retains_each_codec_failure_without_empty_success() {
        for ready_after in [2, 4] {
            let mut fixture = Fixture::new();
            let model = graph_model();
            model.borrow_mut().codec_ready_after_resets = ready_after;
            let mut controller = create(&model, &mut fixture, retry_config(3)).unwrap();
            let start = model.borrow().clock.now_us();
            let result = controller.discover_codecs();
            let failures = if ready_after == 2 {
                let result = result.unwrap();
                assert_eq!(result.attempts, 2);
                assert_eq!(result.codecs.len(), 1);
                assert_eq!(result.codecs[0].token, controller.token);
                assert_eq!(controller.token.generation, 2);
                result.failures
            } else {
                let failure = result.unwrap_err();
                assert_eq!(failure.attempts, 3);
                assert_eq!(failure.error, Error::InvalidCodecGraph);
                assert_eq!(controller.token.generation, 3);
                failure.failures
            };
            assert!(model.borrow().clock.now_us() - start >= 80);
            assert_eq!(failures.len(), if ready_after == 2 { 1 } else { 3 });
            for (index, failure) in failures.iter().enumerate() {
                assert_eq!(
                    *failure,
                    CodecFailure {
                        attempt: index as u8 + 1,
                        address: 0,
                        error: Error::InvalidCodecGraph
                    }
                );
            }
        }
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().advertised_codecs = 0;
        let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
        let failure = controller.discover_codecs().unwrap_err();
        assert_eq!(failure.attempts, 2);
        assert_eq!(failure.error, Error::CodecAbsent);
        assert!(failure.failures.is_empty());
        assert!(model.borrow().commands.is_empty());
    }

    #[test]
    fn discovery_retains_partial_codec_failures_and_resets_poison_before_any_new_command() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().advertised_codecs = 3;
        model
            .borrow_mut()
            .codec_vendor_overrides
            .insert(1, u32::MAX);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let result = controller.discover_codecs().unwrap();
        assert_eq!(result.codecs.len(), 1);
        assert_eq!(result.codecs[0].address, 0);
        assert_eq!(
            result.failures,
            [CodecFailure {
                attempt: 1,
                address: 1,
                error: Error::InvalidCodecGraph
            }]
        );

        let model = graph_model();
        model.borrow_mut().advertised_codecs = 3;
        model.borrow_mut().drop_reply_until_resets = 2;
        let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
        let result = controller.discover_codecs().unwrap();
        assert_eq!(result.attempts, 2);
        assert_eq!(result.codecs.len(), 2);
        assert_eq!(
            result.failures,
            [CodecFailure {
                attempt: 1,
                address: 0,
                error: Error::Timeout(Phase::Verb)
            }]
        );
        assert_eq!(model.borrow().commands[0] >> 28, 0);
        assert_eq!(model.borrow().commands[1] >> 28, 0);
        assert_eq!(controller.token.generation, 2);
        assert!(!controller.command_poisoned);
    }

    #[test]
    fn discovery_retry_quiescence_failure_is_final_and_preserves_original_error_history() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().codec_ready_after_resets = 2;
        let mut controller = create(&model, &mut fixture, retry_config(3)).unwrap();
        model.borrow_mut().command_stop_stuck = true;
        let failure = controller.discover_codecs().unwrap_err();
        assert_eq!(failure.attempts, 1);
        assert_eq!(failure.error, Error::Timeout(Phase::CommandStop));
        assert_eq!(
            failure.failures,
            [CodecFailure {
                attempt: 1,
                address: 0,
                error: Error::InvalidCodecGraph
            }]
        );
        assert_eq!(model.borrow().commands.len(), 1);
        let before = access_counts(&model);
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        assert_eq!(
            controller.discover_codecs().unwrap_err().error,
            Error::NeedsReset
        );
        assert_eq!(access_counts(&model), before);
    }

    fn access_counts(model: &Rc<RefCell<Model>>) -> (usize, usize, usize) {
        let m = model.borrow();
        (m.reads, m.writes.len(), m.commands.len())
    }

    #[test]
    fn reinitialize_invalidates_reused_stream_tags_graphs_and_routes_before_register_access() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let old = controller
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
            .configure_analog_route(&graph, &route, old, 0, options)
            .unwrap();
        controller.start(old).unwrap();
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert!(controller.streams.iter().all(Option::is_none));
        let fresh_graph = controller.enumerate_codec(0).unwrap();
        let fresh = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        assert_eq!(fresh.descriptor_index(), old.descriptor_index());
        assert_eq!(fresh.tag(), old.tag());
        assert_ne!(fresh, old);
        let before = access_counts(&model);
        assert_eq!(controller.start(old), Err(Error::InvalidStream));
        assert_eq!(controller.stop(old), Err(Error::InvalidStream));
        assert_eq!(controller.status(old), Err(Error::InvalidStream));
        assert_eq!(controller.position(old), Err(Error::InvalidStream));
        assert_eq!(
            controller.write_pcm(old, 0, &[1]),
            Err(Error::InvalidStream)
        );
        assert_eq!(
            controller.bind_converter(&graph, 2, fresh, 0),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(
            controller.configure_analog_route(&graph, &route, fresh, 0, options),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(
            controller.configure_analog_route(&fresh_graph, &route, fresh, 0, options),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(access_counts(&model), before);
        let fresh_route = fresh_graph.analog_route(Direction::Playback, 4, 2).unwrap();
        controller
            .configure_analog_route(&fresh_graph, &fresh_route, fresh, 0, options)
            .unwrap();
        controller.start(fresh).unwrap();
    }

    #[test]
    fn failed_reinitialize_quiescence_keeps_reservations_dma_and_blocks_normal_operations() {
        for command_stop in [false, true] {
            let mut fixture = Fixture::new();
            let model = analog_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let id = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller
                .configure_analog_route(
                    &graph,
                    &route,
                    id,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None,
                    },
                )
                .unwrap();
            controller.start(id).unwrap();
            let token = controller.token;
            let descriptor = stream_base(id.descriptor_index());
            let bdl = model
                .borrow()
                .address(descriptor + SD_BDLPL, descriptor + SD_BDLPU);
            if command_stop {
                model.borrow_mut().command_stop_stuck = true;
            } else {
                model.borrow_mut().stream_stop_stuck = true;
            }
            assert_eq!(
                controller.reinitialize(),
                Err(Error::Timeout(if command_stop {
                    Phase::CommandStop
                } else {
                    Phase::StreamStop
                }))
            );
            assert_eq!(controller.token, token);
            assert_eq!(controller.routes.len(), 1);
            let stream = controller.streams[usize::from(id.descriptor_index())]
                .as_ref()
                .unwrap();
            assert_eq!(
                model
                    .borrow()
                    .address(descriptor + SD_BDLPL, descriptor + SD_BDLPU),
                bdl
            );
            assert!(stream.poisoned);
            let before = access_counts(&model);
            let remaining = fixture.allocator.remaining();
            assert_eq!(controller.write_pcm(id, 0, &[1]), Err(Error::NeedsReset));
            assert_eq!(controller.start(id), Err(Error::NeedsReset));
            assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
            assert_eq!(
                controller.enumerate_codec(0).unwrap_err(),
                Error::NeedsReset
            );
            assert_eq!(
                controller.allocate_stream(
                    Direction::Capture,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(fixture.allocator.remaining(), remaining);
            assert_eq!(access_counts(&model), before);
            model.borrow_mut().command_stop_stuck = false;
            model.borrow_mut().stream_stop_stuck = false;
            controller.reinitialize().unwrap();
            assert!(controller.routes.is_empty());
            assert_eq!(controller.start(id), Err(Error::InvalidStream));
            controller.enumerate_codec(0).unwrap();
        }
    }

    #[test]
    fn reinitialize_reset_failure_blocks_until_explicit_recovery_and_generation_never_wraps() {
        let mut fixture = Fixture::new();
        let model = graph_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let id = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        model.borrow_mut().reset_exit_stuck = true;
        assert_eq!(
            controller.reinitialize(),
            Err(Error::Timeout(Phase::LinkResetExit))
        );
        assert_eq!(controller.token.generation, 2);
        let before = access_counts(&model);
        assert_eq!(controller.start(id), Err(Error::InvalidStream));
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().reset_exit_stuck = false;
        controller.reinitialize().unwrap();
        controller.enumerate_codec(0).unwrap();
        controller.token.generation = u64::MAX;
        let before = access_counts(&model);
        assert_eq!(controller.reinitialize(), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
    }

    fn realtek_desktop_model(id: u32) -> Rc<RefCell<Model>> {
        let model = analog_model();
        {
            let mut m = model.borrow_mut();
            m.parameters.insert((0, 0), id);
            m.parameters.insert((1, 4), (2 << 16) | 31);
            m.parameters.insert((0x20, 9), (15 << 20) | (1 << 6));
            for index in [4, 7, 10] {
                m.coefficients.insert((0x20, index), u16::MAX);
            }
        }
        model
    }

    fn realtek_headphone_model(id: u32, present: bool) -> Rc<RefCell<Model>> {
        let model = realtek_desktop_model(id);
        {
            let mut m = model.borrow_mut();
            m.pin_defaults.insert(4, 0x0221_4030);
            m.pin_senses.insert(4, if present { 1 << 31 } else { 0 });
            m.parameters.insert((4, 0x0c), 0x1001c);
            *m.parameters.get_mut(&(4, 9)).unwrap() |= 1 << 10;
            m.parameters.insert((4, 0x0f), 1);
            m.coefficients.insert((0x20, 0x10), 0xa7ff);
        }
        model
    }

    fn realtek_two_sense_model(id: u32, first: bool, second: bool) -> Rc<RefCell<Model>> {
        let model = realtek_headphone_model(id, first);
        {
            let mut m = model.borrow_mut();
            m.parameters.insert((0x16, 9), (4 << 20) | 0x10d);
            // PIN_OUT and AMP_OUT_UNMUTE require neither HP_EN nor mute support.
            m.parameters.insert((0x16, 0x0c), 0x15);
            m.parameters.insert((0x16, 0x12), 0x1f1f);
            m.parameters.insert((0x16, 0x0e), 1);
            m.parameters.insert((8, 9), 5);
            m.connection_words.insert((0x16, 0), 8);
            m.pin_defaults.insert(0x16, 0x4111_11f0); // Actual NoConnection.
            m.pin_senses
                .insert(0x16, if second { 0x8000_0123 } else { 0x123 });
            for (index, value) in [
                (0, 0),
                (0x38, 0xab7f),
                (0x0d, 0xb7ff),
                (0x36, 0xaaff),
                (0x67, 0xdead),
                (0x4a, 0x2fff),
            ] {
                m.coefficients.insert((0x20, index), value);
            }
            m.coefficients.insert((0x58, 3), 0xa53f);
            m.coefficients.insert((0x57, 4), 0xab07);
            m.depop_delay_us = Some(100_000);
            m.depop_mutate_saved = true;
        }
        model
    }

    fn headphone_binding(route: &AnalogRoute, stream: StreamId) -> RealtekHeadphoneRoute<'_> {
        RealtekHeadphoneRoute {
            route,
            stream,
            channel: 0,
            options: PinOptions::Playback {
                headphone: true,
                eapd: None,
            },
        }
    }

    #[test]
    fn alc285_and_295_single_route_observes_raw_second_pin_and_orders_actual_boot_depop() {
        for (id, coefficient_zero, boot_depop) in [
            (0x10ec0285, 0, true),
            (0x10ec0285, 0x10, false),
            (0x10ec0295, 0, true),
        ] {
            for first in [false, true] {
                for second in [false, true] {
                    let mut fixture = Fixture::new();
                    let model = realtek_two_sense_model(id, first, second);
                    model
                        .borrow_mut()
                        .coefficients
                        .insert((0x20, 0), coefficient_zero);
                    let mut controller = create(&model, &mut fixture, config()).unwrap();
                    let graph = controller.enumerate_codec(0).unwrap();
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
                    let began = model.borrow().clock.now_us();
                    let report = controller
                        .configure_realtek_alc285_295_headphones(
                            &graph,
                            headphone_binding(&route, stream),
                            None,
                        )
                        .unwrap();
                    assert_eq!(report.boot_depop_performed, boot_depop);
                    assert_eq!(
                        report.coefficient_zero,
                        if id == 0x10ec0285 {
                            Some(coefficient_zero)
                        } else {
                            None
                        }
                    );
                    assert_eq!(report.headphone_pins, [4, 0x16]);
                    assert_eq!(report.initial_senses[0].present, first);
                    assert_eq!(
                        report.initial_senses[1].raw,
                        if second { 0x8000_0123 } else { 0x123 }
                    );
                    assert_eq!(controller.routes.len(), 1);
                    assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
                    {
                        let m = model.borrow();
                        let sequences: Vec<_> = m
                            .coefficient_events
                            .iter()
                            .filter(|(node, _, _, _)| *node == 0x58)
                            .collect();
                        if boot_depop {
                            assert_eq!(
                                sequences
                                    .iter()
                                    .map(|event| (event.1, event.2))
                                    .collect::<Vec<_>>(),
                                [
                                    (0, 0x1888),
                                    (0, 0x7880),
                                    (0x0f, 0xf049),
                                    (3, 0xa5cf),
                                    (0, 0xf888),
                                    (0, 0x7888)
                                ]
                            );
                            assert!(sequences[1].3 >= sequences[0].3 + 140_000);
                            assert!(sequences[5].3 >= sequences[4].3 + 100_000);
                            assert_eq!(m.coefficients[&(0x20, 0x38)], 0xab7f);
                            assert_eq!(m.coefficients[&(0x20, 0x0d)], 0xb7ff);
                            assert_eq!(m.coefficients[&(0x20, 0x36)], 0x8aff);
                        } else {
                            assert!(sequences.is_empty());
                        }
                        let sense = m
                            .command_times
                            .iter()
                            .find(|(command, _)| {
                                (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09
                            })
                            .unwrap()
                            .1;
                        assert!(sense >= began + if boot_depop { 320_000 } else { 30_000 });
                        let pin16_writes: Vec<_> = m
                            .command_times
                            .iter()
                            .filter(|(command, _)| {
                                (command >> 20) & 127 == 0x16
                                    && ((command >> 8) & 0xfff == 0x707
                                        || (command >> 16) & 15 == 3)
                            })
                            .collect();
                        assert_eq!(pin16_writes.len(), if second { 2 } else { 0 });
                        if second {
                            assert!(pin16_writes[0].1 >= sense + 2_000);
                            assert!(pin16_writes[1].1 >= pin16_writes[0].1 + 75_000);
                        }
                        let power: Vec<_> = m
                            .coefficient_events
                            .iter()
                            .filter(|(node, _, _, _)| *node == 0x57)
                            .collect();
                        assert_eq!(power.len(), if first || second { 2 } else { 0 });
                        if first || second {
                            assert_eq!((power[0].2, power[1].2), (0xab01, 0xab04));
                            assert!(power[1].3 >= power[0].3 + 150_000);
                        }
                    }
                    let second_stream = controller
                        .allocate_stream(
                            Direction::Playback,
                            stereo(),
                            128,
                            2,
                            &mut fixture.allocator,
                        )
                        .unwrap();
                    let reuse = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
                    let before = access_counts(&model);
                    assert_eq!(
                        controller.configure_analog_route(
                            &graph,
                            &reuse,
                            second_stream,
                            0,
                            PinOptions::Playback {
                                headphone: false,
                                eapd: None
                            }
                        ),
                        Err(Error::RouteInUse)
                    );
                    assert_eq!(
                        controller.bind_converter(&graph, 0x16, second_stream, 0),
                        Err(Error::RouteInUse)
                    );
                    assert_eq!(access_counts(&model), before);
                    controller.write_pcm(stream, 0, &[0x7c; 256]).unwrap();
                    controller.start(stream).unwrap();
                    model.borrow_mut().dma_step_bytes = 128;
                    advance(&model, 4);
                    assert!(controller.status(stream).unwrap().period_completed);
                    controller.stop(stream).unwrap();
                    assert!(model.borrow().playback.len() >= 256);
                    assert!(model.borrow().playback.iter().all(|byte| *byte == 0x7c));
                    controller.reinitialize().unwrap();
                    assert!(controller.codec_controls.is_empty());
                    let before = access_counts(&model);
                    assert_eq!(
                        controller.configure_realtek_alc285_295_headphones(
                            &graph,
                            headphone_binding(&route, stream),
                            None
                        ),
                        Err(Error::InvalidCodecGraph)
                    );
                    assert_eq!(access_counts(&model), before);
                }
            }
        }
    }

    #[test]
    fn alc295_optional_real_second_route_does_not_require_a_headphone_enable_bit() {
        let mut fixture = Fixture::new();
        let model = realtek_two_sense_model(0x10ec0295, true, true);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let first = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let second = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
        let playback = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let other = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let mut second_binding = headphone_binding(&second, other);
        second_binding.options = PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        let report = controller
            .configure_realtek_alc285_295_headphones(
                &graph,
                headphone_binding(&first, playback),
                Some(second_binding),
            )
            .unwrap();
        assert!(report.initial_senses[1].present);
        assert_eq!(controller.routes.len(), 2);
        assert!(controller.codec_controls.is_empty());
        assert_eq!(model.borrow().bindings[&8], (other.tag() << 4));
        assert_eq!(model.borrow().route_controls[&(0x16, 0xf07)], 0x40);
        controller.write_pcm(playback, 0, &[0x31; 256]).unwrap();
        controller.write_pcm(other, 0, &[0x31; 256]).unwrap();
        controller.start(playback).unwrap();
        controller.start(other).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 4);
        controller.stop(playback).unwrap();
        controller.stop(other).unwrap();
        assert!(model.borrow().playback.len() >= 512);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x31));
        controller.shutdown().unwrap();
    }

    #[test]
    fn alc295_depop_timeout_and_staged_fixed_sequencer_failures_quarantine_until_reset() {
        for stage in 0..9 {
            let mut fixture = Fixture::new();
            let model = realtek_two_sense_model(0x10ec0295, true, true);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            {
                let mut m = model.borrow_mut();
                if stage == 0 {
                    m.depop_delay_us = None;
                } else if stage <= 6 {
                    m.coefficient_read_fault = Some(u32::MAX);
                    m.coefficient_fault_node = Some(0x58);
                    m.coefficient_fault_after_write = true;
                    m.coefficient_fault_write_threshold = stage;
                } else if stage == 7 {
                    m.coefficient_index_reply = Some((0x58, u32::MAX));
                } else {
                    m.reject_coefficient_node = Some(0x58);
                }
            }
            let began = model.borrow().clock.now_us();
            let error = controller
                .configure_realtek_alc285_295_headphones(
                    &graph,
                    headphone_binding(&route, stream),
                    None,
                )
                .unwrap_err();
            assert_eq!(
                error,
                if stage == 0 {
                    Error::Timeout(Phase::CodecDepop)
                } else {
                    Error::CoefficientRejected {
                        node: 0x58,
                        index: if stage == 3 {
                            0x0f
                        } else if stage == 4 {
                            3
                        } else {
                            0
                        },
                    }
                }
            );
            if stage == 0 {
                let elapsed = model.borrow().clock.now_us() - began;
                assert!((1_140_000..1_145_000).contains(&elapsed));
            }
            assert!(controller.routing_failed);
            assert!(controller.routes.is_empty() && controller.codec_controls.is_empty());
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(
                controller.configure_realtek_alc285_295_headphones(
                    &graph,
                    headphone_binding(&route, stream),
                    None
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
            if stage == 0 {
                model.borrow_mut().depop_delay_us = Some(0);
                controller.reinitialize().unwrap();
                let fresh = controller.enumerate_codec(0).unwrap();
                let route = fresh.analog_route(Direction::Playback, 4, 2).unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                controller
                    .configure_realtek_alc285_295_headphones(
                        &fresh,
                        headphone_binding(&route, stream),
                        None,
                    )
                    .unwrap();
                assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
                controller.start(stream).unwrap();
                model.borrow_mut().stream_stop_stuck = true;
                assert_eq!(
                    controller.reinitialize(),
                    Err(Error::Timeout(Phase::StreamStop))
                );
                assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
                model.borrow_mut().stream_stop_stuck = false;
                controller.reinitialize().unwrap();
                assert!(controller.codec_controls.is_empty());
            }
        }
    }

    #[test]
    fn alc295_live_fixed_pin_and_conditional_output_capabilities_are_not_invented() {
        for case in 0..5 {
            let mut fixture = Fixture::new();
            let model = realtek_two_sense_model(0x10ec0295, false, case != 4);
            if case >= 2 {
                let mut m = model.borrow_mut();
                m.parameters.insert((0x16, 0x0c), 4); // Sensing only, no output capability.
                m.parameters.insert((0x16, 9), (4 << 20) | 1); // No amplifier.
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            if case == 0 {
                model.borrow_mut().parameters.insert((0x16, 9), u32::MAX);
            }
            if case == 1 {
                model.borrow_mut().parameters.insert((0x16, 0x0c), 0x1d);
            }
            if case == 3 {
                model.borrow_mut().pin_senses.insert(0x16, u32::MAX);
            }
            let result = controller.configure_realtek_alc285_295_headphones(
                &graph,
                headphone_binding(&route, stream),
                None,
            );
            if case < 2 {
                assert_eq!(result, Err(Error::InvalidCodecGraph));
                assert!(model.borrow().coefficient_events.is_empty());
                assert!(!controller.routing_failed);
            } else if case < 4 {
                assert_eq!(result, Err(Error::UnsupportedTopology));
                assert!(controller.routing_failed);
                assert!(
                    !model
                        .borrow()
                        .command_times
                        .iter()
                        .any(|(command, _)| (command >> 20) & 127 == 0x16
                            && ((command >> 8) & 0xfff == 0x707 || (command >> 16) & 15 == 3))
                );
            } else {
                assert_eq!(result.unwrap().initial_senses[1].raw, 0x123);
                assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
            }
        }
    }

    #[test]
    fn alc295_optional_route_preflight_and_partial_second_route_failure_keep_ownership_explicit() {
        for conflict in [true, false] {
            let mut fixture = Fixture::new();
            let model = realtek_two_sense_model(0x10ec0295, false, false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let first = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let second = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let other = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let mut binding = headphone_binding(&second, if conflict { stream } else { other });
            binding.options = PinOptions::Playback {
                headphone: false,
                eapd: None,
            };
            if !conflict {
                let mut m = model.borrow_mut();
                m.reject_route_control = Some(0xf07);
                m.reject_route_node = Some(0x16);
            }
            let before = access_counts(&model);
            let result = controller.configure_realtek_alc285_295_headphones(
                &graph,
                headphone_binding(&first, stream),
                Some(binding),
            );
            if conflict {
                assert_eq!(result, Err(Error::RouteInUse));
                assert_eq!(access_counts(&model), before);
                assert!(!controller.routing_failed);
            } else {
                assert_eq!(result, Err(Error::RouteRejected));
                assert!(controller.routing_failed);
                assert_eq!(controller.routes, [(stream, first.clone())]);
                assert!(controller.codec_controls.is_empty());
                let before = access_counts(&model);
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                assert_eq!(controller.start(other), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
            }
        }
    }

    #[test]
    fn alc255_depop_preserves_eapd_passthrough_until_the_final_literal_and_reserves_real_pcm() {
        for present in [false, true] {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0255, present);
            {
                let mut m = model.borrow_mut();
                m.coefficients.insert((0x20, 0x36), 0xaaff);
                m.coefficients.insert((0x20, 0x46), 0xb5a5);
                m.coefficients.insert((0x57, 4), 0xab07);
                m.coefficients.insert((0x53, 2), 0x9234);
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            let options = PinOptions::Playback {
                headphone: true,
                eapd: Some(true),
            };
            let before = access_counts(&model);
            assert_eq!(
                controller.configure_realtek_alc256_headphone(&graph, &route, stream, 0, options),
                Err(Error::UnsupportedTopology)
            );
            assert_eq!(access_counts(&model), before);
            let start = model.borrow().clock.now_us();
            let report = controller
                .configure_realtek_alc255_headphone(&graph, &route, stream, 0, options)
                .unwrap();
            assert_eq!(report.common.codec_id, 0x10ec0255);
            assert_eq!(report.initial_sense.present, present);
            assert_eq!(
                report
                    .common
                    .coefficients
                    .iter()
                    .map(|c| c.index)
                    .collect::<Vec<_>>(),
                [0x10, 0x46, 0x36]
            );
            assert_eq!(report.common.coefficients[2].previous, 0xaaff);
            assert_eq!(report.common.coefficients[2].current, 0x5757);
            {
                let m = model.borrow();
                let events = &m.coefficient_events;
                let literal: Vec<_> = events
                    .iter()
                    .filter(|(node, index, _, _)| *node == 0x20 && *index == 0x36)
                    .collect();
                assert_eq!(literal.len(), 1);
                let reset: Vec<_> = events
                    .iter()
                    .filter(|(node, _, _, _)| *node == 0x53)
                    .collect();
                assert_eq!(reset.len(), 2);
                assert_eq!((reset[0].2, reset[1].2), (0x9234, 0x1234));
                assert!(reset[0].3 < reset[1].3 && reset[1].3 < literal[0].3);
                let hp: Vec<_> = events
                    .iter()
                    .filter(|(node, _, _, _)| *node == 0x57)
                    .collect();
                assert_eq!(hp.len(), if present { 2 } else { 0 });
                if present {
                    assert_eq!((hp[0].2, hp[1].2), (0xab01, 0xab04));
                    assert!(hp[0].3 >= start + 32_000);
                    assert!(hp[1].3 >= hp[0].3 + 150_000);
                }
                assert_eq!(m.coefficients[&(0x20, 0x10)], 0xa5ff);
                assert_eq!(m.coefficients[&(0x20, 0x46)], 0x85a5);
            }
            assert_eq!(controller.routes.len(), 1);
            controller.write_pcm(stream, 0, &[0x5b; 256]).unwrap();
            controller.start(stream).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 4);
            assert!(controller.status(stream).unwrap().period_completed);
            controller.stop(stream).unwrap();
            assert!(model.borrow().playback.len() >= 256);
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5b));
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn alc255_live_identity_and_late_depop_failure_do_not_publish_a_route() {
        for fault in 0..3 {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0255, true);
            model.borrow_mut().coefficients.insert((0x53, 2), 0x1234);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            {
                let mut m = model.borrow_mut();
                if fault == 0 {
                    m.parameters.insert((0, 0), 0x10ec0256);
                } else {
                    m.coefficient_read_fault = Some(u32::MAX);
                    m.coefficient_fault_node = Some(0x53);
                    m.coefficient_fault_after_write = true;
                    m.coefficient_fault_write_threshold = fault;
                }
            }
            let result = controller.configure_realtek_alc255_headphone(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: None,
                },
            );
            assert_eq!(
                result,
                Err(if fault == 0 {
                    Error::InvalidCodecGraph
                } else {
                    Error::CoefficientRejected {
                        node: 0x53,
                        index: 2,
                    }
                })
            );
            assert!(controller.routes.is_empty());
            if fault == 0 {
                assert!(model.borrow().coefficient_events.is_empty());
                assert!(!controller.routing_failed);
            } else {
                assert!(controller.routing_failed);
                assert_eq!(model.borrow().coefficient_write_nodes[&0x53], fault);
                let before = access_counts(&model);
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
            }
        }
    }

    #[test]
    fn alc256_and_257_depop_use_fixed_nodes_ordered_reset_edges_and_timed_stereo_route() {
        for id in [0x10ec0256, 0x10ec0257] {
            for present in [false, true] {
                for reset_already_high in [false, true] {
                    let mut fixture = Fixture::new();
                    let model = realtek_headphone_model(id, present);
                    {
                        let mut m = model.borrow_mut();
                        m.coefficients.insert((0x57, 4), 0xab07);
                        m.coefficients
                            .insert((0x53, 2), if reset_already_high { 0x9234 } else { 0x1234 });
                        m.coefficients.insert((0x20, 0x36), 0xaaff);
                        m.coefficients.insert((0x20, 0x46), 0xb5a5);
                    }
                    let mut controller = create(&model, &mut fixture, config()).unwrap();
                    let graph = controller.enumerate_codec(0).unwrap();
                    let route = graph
                        .analog_endpoints(Direction::Playback, stereo())
                        .unwrap()
                        .remove(0)
                        .route;
                    let stream = controller
                        .allocate_stream(
                            Direction::Playback,
                            stereo(),
                            128,
                            2,
                            &mut fixture.allocator,
                        )
                        .unwrap();
                    let start = model.borrow().clock.now_us();
                    let report = controller
                        .configure_realtek_alc256_headphone(
                            &graph,
                            &route,
                            stream,
                            0,
                            PinOptions::Playback {
                                headphone: true,
                                eapd: Some(true),
                            },
                        )
                        .unwrap();
                    assert_eq!(report.common.codec_id, id);
                    assert_eq!(report.initial_sense.present, present);
                    let m = model.borrow();
                    assert_eq!(m.coefficients[&(0x20, 0x36)], 0x5757);
                    assert_eq!(m.coefficients[&(0x20, 0x46)], 0x85a5);
                    assert_eq!(m.coefficients[&(0x20, 0x10)], 0xa5ff);
                    assert_eq!(m.coefficients[&(0x53, 2)], 0x1234);
                    assert_eq!(
                        m.coefficients[&(0x57, 4)],
                        if present { 0xab04 } else { 0xab07 }
                    );
                    let reset: Vec<_> = m
                        .coefficient_events
                        .iter()
                        .filter(|(node, _, _, _)| *node == 0x53)
                        .collect();
                    // Do not optimize away an already-high first write.
                    assert_eq!(reset.len(), 2);
                    assert_eq!((reset[0].1, reset[0].2), (2, 0x9234));
                    assert_eq!((reset[1].1, reset[1].2), (2, 0x1234));
                    assert!(reset[0].3 < reset[1].3);
                    let hp: Vec<_> = m
                        .coefficient_events
                        .iter()
                        .filter(|(node, _, _, _)| *node == 0x57)
                        .collect();
                    assert_eq!(hp.len(), if present { 2 } else { 0 });
                    let sense = m
                        .command_times
                        .iter()
                        .find(|(command, _)| {
                            (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09
                        })
                        .unwrap()
                        .1;
                    assert!(sense >= start + 30_000);
                    if present {
                        assert_eq!((hp[0].1, hp[0].2), (4, 0xab01));
                        assert_eq!((hp[1].1, hp[1].2), (4, 0xab04));
                        let pin = m
                            .command_times
                            .iter()
                            .find(|(command, _)| {
                                (command >> 20) & 127 == 4
                                    && (command >> 8) & 0xfff == 0x707
                                    && *command as u8 == 0x40
                            })
                            .unwrap()
                            .1;
                        let amp = m
                            .command_times
                            .iter()
                            .find(|(command, _)| {
                                (command >> 20) & 127 == 4
                                    && (command >> 16) & 15 == 3
                                    && *command as u16 == 0xb000
                            })
                            .unwrap()
                            .1;
                        assert!(hp[0].3 >= sense + 2_000 && pin > hp[0].3);
                        assert!(amp >= pin + 75_000);
                        assert!(hp[1].3 >= amp + 75_000);
                        assert!(reset[0].3 > hp[1].3);
                    }
                    let final_36 = m
                        .coefficient_events
                        .iter()
                        .rfind(|(node, index, _, _)| *node == 0x20 && *index == 0x36)
                        .unwrap();
                    assert_eq!(final_36.2, 0x5757);
                    assert!(final_36.3 > reset[1].3);
                    assert!(
                        m.coefficient_events
                            .iter()
                            .all(|(node, _, _, _)| matches!(node, 0x20 | 0x53 | 0x57))
                    );
                    drop(m);
                    assert_eq!(controller.routes.len(), 1);
                    // Add capture after startup: the existing common reservation
                    // scheme still permits a separate explicit ADC/pin path.
                    let capture = controller
                        .allocate_stream(
                            Direction::Capture,
                            stereo(),
                            128,
                            2,
                            &mut fixture.allocator,
                        )
                        .unwrap();
                    let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
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
                    controller.fill_capture(capture, 0xa5).unwrap();
                    controller.write_pcm(stream, 0, &[0x69; 256]).unwrap();
                    controller.start(stream).unwrap();
                    controller.start(capture).unwrap();
                    model.borrow_mut().dma_step_bytes = 128;
                    advance(&model, 4);
                    assert!(controller.status(stream).unwrap().period_completed);
                    controller.stop(stream).unwrap();
                    controller.stop(capture).unwrap();
                    assert!(model.borrow().playback.len() >= 256);
                    assert!(model.borrow().playback.iter().all(|byte| *byte == 0x69));
                    let mut bytes = [0; 256];
                    controller.read_pcm(capture, 0, &mut bytes).unwrap();
                    assert_eq!(bytes, core::array::from_fn(|index| index as u8));
                    controller.shutdown().unwrap();
                }
            }
        }
    }

    #[test]
    fn alc256_fixed_power_reset_index_data_and_each_pulse_readback_failure_quarantine_start() {
        for fault in 0..10 {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0256, true);
            {
                let mut m = model.borrow_mut();
                m.coefficients.insert((0x57, 4), 0xab07);
                m.coefficients.insert((0x53, 2), 0x1234);
                if fault < 6 {
                    m.coefficient_read_fault = Some(if fault == 5 { 0x1ffff } else { u32::MAX });
                    m.coefficient_fault_node = Some(if fault == 0 || fault == 1 || fault == 5 {
                        0x57
                    } else {
                        0x53
                    });
                    m.coefficient_fault_after_write = matches!(fault, 1 | 3 | 4);
                    m.coefficient_fault_write_threshold = if fault == 4 { 2 } else { 1 };
                } else if fault < 8 {
                    m.reject_coefficient_node = Some(if fault == 6 { 0x57 } else { 0x53 });
                } else {
                    m.coefficient_index_reply = Some((
                        if fault == 8 { 0x57 } else { 0x53 },
                        if fault == 8 { 0 } else { u32::MAX },
                    ));
                }
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            let node = if matches!(fault, 0 | 1 | 5 | 6 | 8) {
                0x57
            } else {
                0x53
            };
            assert_eq!(
                controller
                    .configure_realtek_alc256_headphone(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: None
                        }
                    )
                    .unwrap_err(),
                Error::CoefficientRejected {
                    node,
                    index: if node == 0x57 { 4 } else { 2 }
                }
            );
            assert!(controller.routing_failed);
            assert!(controller.routes.is_empty());
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(
                controller.configure_realtek_alc256_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None
                    }
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
            if fault == 3 {
                {
                    let mut m = model.borrow_mut();
                    m.coefficient_read_fault = None;
                    m.coefficient_index_reply = None;
                    m.reject_coefficient_node = None;
                }
                controller.reinitialize().unwrap();
                let fresh = controller.enumerate_codec(0).unwrap();
                let route = fresh.analog_route(Direction::Playback, 4, 2).unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                controller
                    .configure_realtek_alc256_headphone(
                        &fresh,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: None,
                        },
                    )
                    .unwrap();
                assert_eq!(controller.routes.len(), 1);
            }
        }
    }

    #[test]
    fn alc298_explicit_headphone_startup_observes_source_delays_and_reserves_real_route() {
        for present in [false, true] {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0298, present);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph
                .analog_endpoints(Direction::Playback, stereo())
                .unwrap()
                .remove(0)
                .route;
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let start = model.borrow().clock.now_us();
            let report = controller
                .configure_realtek_alc298_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: Some(true),
                    },
                )
                .unwrap();
            assert_eq!(report.common.codec_id, 0x10ec0298);
            assert_eq!(report.headphone_pin, 4);
            assert_eq!(report.initial_sense.present, present);
            assert_eq!(report.common.coefficients[0].current, 0xa5ff);
            let m = model.borrow();
            let find = |predicate: fn(u32) -> bool| {
                m.command_times
                    .iter()
                    .find(|(command, _)| predicate(*command))
                    .map(|(_, time)| *time)
            };
            let sense_time =
                find(|command| (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09)
                    .unwrap();
            assert!(sense_time >= start + 30_000);
            let pin_time = find(|command| {
                (command >> 20) & 127 == 4
                    && (command >> 8) & 0xfff == 0x707
                    && command as u8 == 0x40
            });
            let amp_time = find(|command| {
                (command >> 20) & 127 == 4 && (command >> 16) & 15 == 3 && command as u16 == 0xb000
            });
            assert_eq!(pin_time.is_some(), present);
            assert_eq!(amp_time.is_some(), present);
            if present {
                assert!(pin_time.unwrap() >= sense_time + 2_000);
                assert!(amp_time.unwrap() >= pin_time.unwrap() + 75_000);
                let generic_power = m
                    .command_times
                    .iter()
                    .find(|(command, time)| {
                        *time > amp_time.unwrap() && (command >> 8) & 0xfff == 0x705
                    })
                    .unwrap()
                    .1;
                assert!(generic_power >= amp_time.unwrap() + 75_000);
            }
            assert!(m.power_ready.contains_key(&4));
            assert_eq!(m.route_controls[&(4, 0xf07)], 0xc0);
            assert_eq!(m.route_controls[&(4, 0xf0c)], 7);
            drop(m);
            assert_eq!(controller.routes.len(), 1);
            let before = access_counts(&model);
            assert_eq!(
                controller.configure_realtek_alc298_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None
                    }
                ),
                Err(Error::RouteInUse)
            );
            assert_eq!(access_counts(&model), before);
            controller.write_pcm(stream, 0, &[0x46; 256]).unwrap();
            controller.start(stream).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 4);
            assert!(controller.status(stream).unwrap().period_completed);
            controller.stop(stream).unwrap();
            assert!(model.borrow().playback.len() >= 256);
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x46));
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn alc298_startup_rechecks_live_pin_policy_and_stale_stream_before_any_mutation() {
        for fault in 0..7 {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0298, true);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph
                .analog_endpoints(Direction::Playback, stereo())
                .unwrap()
                .remove(0)
                .route;
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let mut options = PinOptions::Playback {
                headphone: true,
                eapd: None,
            };
            match fault {
                0 => {
                    options = PinOptions::Playback {
                        headphone: false,
                        eapd: None,
                    }
                }
                1 => {
                    model.borrow_mut().pin_defaults.insert(4, 0x0101_4010);
                }
                2 => {
                    model.borrow_mut().parameters.insert((4, 0x0c), 0x10);
                }
                3 => {
                    model.borrow_mut().parameters.insert((0, 0), 0x10ec0256);
                }
                4 => {
                    model.borrow_mut().parameters.insert((0x51, 0), 0x10ec5505);
                }
                5 => {
                    model.borrow_mut().parameters.insert((1, 0x12), 0);
                }
                6 => {
                    controller.reinitialize().unwrap();
                }
                _ => unreachable!(),
            }
            let fresh = if fault == 6 {
                Some(controller.enumerate_codec(0).unwrap())
            } else {
                None
            };
            let graph = fresh.as_ref().unwrap_or(&graph);
            let route = if fault == 6 {
                graph.analog_route(Direction::Playback, 4, 2).unwrap()
            } else {
                route
            };
            let before = access_counts(&model);
            assert!(
                controller
                    .configure_realtek_alc298_headphone(graph, &route, stream, 0, options)
                    .is_err()
            );
            if fault == 6 {
                assert_eq!(access_counts(&model), before);
            }
            assert!(
                model.borrow().commands[before.2..]
                    .iter()
                    .all(|command| (command >> 16) & 15 >= 8)
            );
            assert!(model.borrow().coefficient_indexes.is_empty());
            assert!(!controller.routing_failed);
        }
    }

    #[test]
    fn alc298_startup_failures_quarantine_partial_pin_amp_and_common_state() {
        for fault in 0..4 {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec0298, true);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
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
            match fault {
                0 => model.borrow_mut().coefficient_index_failed = true,
                1 => model.borrow_mut().reject_route_control = Some(0xf07),
                2 => model.borrow_mut().reject_amplifier = true,
                3 => model.borrow_mut().power_stuck = true,
                _ => unreachable!(),
            }
            assert!(
                controller
                    .configure_realtek_alc298_headphone(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: None
                        }
                    )
                    .is_err()
            );
            assert!(controller.routing_failed);
            assert!(controller.routes.is_empty());
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(
                controller.configure_realtek_alc298_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None
                    }
                ),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
        }
    }

    #[test]
    fn alc269_live_silicon_variants_use_exact_pll_eapd_and_revision_controls() {
        for (zero, variant) in [
            (0x0000, Alc269Variant::Va),
            (0x0014, Alc269Variant::Vb),
            (0x0016, Alc269Variant::Vb),
            (0x0017, Alc269Variant::Vb),
            (0x0018, Alc269Variant::Vb),
            (0x0020, Alc269Variant::Vc),
            (0x0030, Alc269Variant::Vd),
        ] {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0269);
            {
                let mut m = model.borrow_mut();
                for (index, value) in [
                    (0, zero),
                    (4, 0x8021),
                    (0x0d, 0x0030),
                    (0x10, u16::MAX),
                    (0x17, 0x0050),
                ] {
                    m.coefficients.insert((0x20, index), value);
                }
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            assert!(matches!(
                controller.initialize_realtek_common(&graph),
                Err(Error::UnsupportedTopology)
            ));
            let report = controller.initialize_realtek_alc269_common(&graph).unwrap();
            assert_eq!(report.coefficient_zero, zero);
            assert_eq!(report.variant, variant);
            assert_eq!(report.common.codec_id, 0x10ec0269);
            let m = model.borrow();
            match variant {
                Alc269Variant::Va | Alc269Variant::Vc => {
                    assert_eq!(m.coefficients[&(0x20, 4)], 0x0021)
                }
                Alc269Variant::Vd => assert_eq!(m.coefficients[&(0x20, 0x10)], 0xfdff),
                Alc269Variant::Vb => {
                    assert_eq!(m.coefficients[&(0x20, 4)], 0x8821);
                    assert_eq!(
                        m.coefficients[&(0x20, 0x0d)],
                        if zero == 0x18 { 0x4430 } else { 0x4030 }
                    );
                    if zero < 0x15 || zero == 0x16 {
                        assert_eq!(m.coefficients[&(0x20, 0x0f)], 0x960b);
                        assert_eq!(
                            m.coefficients[&(0x20, 0x0e)],
                            if zero == 0x16 { 0x8814 } else { 0x8817 }
                        );
                    }
                    if zero == 0x18 {
                        assert_eq!(m.coefficients[&(0x20, 0x17)], 0x00d0);
                    }
                }
            }
            let writes = m.coefficient_writes;
            drop(m);
            controller.initialize_realtek_alc269_common(&graph).unwrap();
            // The literal early-VB writes are mandatory transactions even when
            // the last value already equals the donor's desired value.
            if zero == 0x14 || zero == 0x16 {
                assert_eq!(model.borrow().coefficient_writes, writes + 2);
            }
            let endpoint = graph
                .analog_endpoints(Direction::Playback, stereo())
                .unwrap()
                .remove(0);
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller
                .configure_analog_route(
                    &graph,
                    &endpoint.route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None,
                    },
                )
                .unwrap();
            controller.write_pcm(stream, 0, &[0x35; 256]).unwrap();
            controller.start(stream).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 4);
            assert!(controller.status(stream).unwrap().period_completed);
            controller.stop(stream).unwrap();
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x35));
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn alc269_vb18_preserves_the_donor_or_operations_and_does_not_normalize_fields() {
        for (old_d, old_17) in [(0x0420, 0x0110), (0x0c20, 0x0190)] {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0269);
            {
                let mut m = model.borrow_mut();
                m.coefficients.insert((0x20, 0), 0x18);
                m.coefficients.insert((0x20, 0x0d), old_d);
                m.coefficients.insert((0x20, 0x17), old_17);
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_realtek_alc269_common(&graph).unwrap();
            assert_eq!(model.borrow().coefficients[&(0x20, 0x0d)], old_d | 0x4000);
            assert_eq!(model.borrow().coefficients[&(0x20, 0x17)], old_17);
            assert_eq!(
                report
                    .common
                    .coefficients
                    .iter()
                    .filter(|change| change.index == 0x17)
                    .count(),
                usize::from(old_17 & 0x1c0 != 0x100)
            );
        }
    }

    #[test]
    fn alc269_companion_dsp_or_unknown_companion_identity_refuses_before_any_codec_mutation() {
        for identity in [0x10ec5505, 0x12345678, u32::MAX] {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0269);
            model.borrow_mut().parameters.insert((0x51, 0), identity);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let before = model.borrow().commands.len();
            assert_eq!(
                controller.initialize_realtek_alc269_common(&graph),
                Err(Error::UnsupportedTopology)
            );
            assert!(
                model.borrow().commands[before..]
                    .iter()
                    .all(|command| (command >> 16) & 15 >= 8)
            );
            assert!(model.borrow().power_ready.is_empty());
            assert!(model.borrow().coefficient_indexes.is_empty());
            assert!(!controller.routing_failed);
        }
    }

    #[test]
    fn alc269_unknown_variant_failed_revision_and_literal_readback_refuse_and_gate_partial_state() {
        for fault in 0..3 {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0269);
            model
                .borrow_mut()
                .coefficients
                .insert((0x20, 0), if fault == 0 { 0x40 } else { 0x14 });
            if fault != 0 {
                model.borrow_mut().coefficient_read_fault = Some(u32::MAX);
                model.borrow_mut().coefficient_fault_after_write = fault == 2;
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let expected = match fault {
                0 => Error::UnsupportedTopology,
                1 => Error::CoefficientRejected {
                    node: 0x20,
                    index: 0,
                },
                _ => Error::CoefficientRejected {
                    node: 0x20,
                    index: 0x0f,
                },
            };
            assert_eq!(
                controller
                    .initialize_realtek_alc269_common(&graph)
                    .unwrap_err(),
                expected
            );
            assert_eq!(model.borrow().coefficient_writes, usize::from(fault == 2));
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            let before = access_counts(&model);
            assert_eq!(
                controller.initialize_realtek_alc269_common(&graph),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
        }
    }

    #[test]
    fn realtek_desktop_common_masks_follow_exact_codec_identity_and_real_indexed_verbs() {
        for (id, expected) in [
            (0x10ec0887, &[(10, 0xfbff)][..]),
            (0x10ec0892, &[(4, 0x7fff), (7, 0xffdf)][..]),
            (0x10ec0897, &[(4, 0x7fff), (7, 0xffdf)][..]),
            (0x10ec0900, &[(7, 0xfffd)][..]),
            (0x10ec1220, &[(7, 0xfffd)][..]),
            (0x10ec1168, &[(10, 0xfbff), (7, 0xfffd)][..]),
        ] {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(id);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_realtek_common(&graph).unwrap();
            assert_eq!(report.codec_id, id);
            assert_eq!(report.revision_id, graph.revision_id);
            assert_eq!(report.subsystem_id, 0x10438693);
            assert_eq!(report.coefficients.len(), expected.len());
            for (change, &(index, value)) in report.coefficients.iter().zip(expected) {
                assert_eq!(
                    (change.index, change.previous, change.current),
                    (index, u16::MAX, value)
                );
                assert_eq!(model.borrow().coefficients[&(0x20, index)], value);
            }
            assert_eq!(model.borrow().coefficient_writes, expected.len());
            assert!(model.borrow().power_ready.contains_key(&1));
            assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5); //No EAPD/pin/GPIO enable.
            let again = controller.initialize_realtek_common(&graph).unwrap();
            assert!(
                again
                    .coefficients
                    .iter()
                    .all(|change| change.previous == change.current)
            );
            assert_eq!(model.borrow().coefficient_writes, expected.len());
            let endpoint = graph
                .analog_endpoints(Direction::Playback, stereo())
                .unwrap()
                .remove(0);
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller
                .configure_analog_route(
                    &graph,
                    &endpoint.route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: Some(true),
                    },
                )
                .unwrap();
            let before = access_counts(&model);
            assert_eq!(
                controller.initialize_realtek_common(&graph),
                Err(Error::RouteInUse)
            );
            assert_eq!(access_counts(&model), before);
            controller.write_pcm(stream, 0, &[0x5a; 256]).unwrap();
            controller.start(stream).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            assert!(controller.status(stream).unwrap().period_completed);
            controller.stop(stream).unwrap();
            assert!(model.borrow().playback.len() >= 256);
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5a));
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn realtek_common_preflight_refuses_forged_stale_live_identity_and_unsupported_vendor_layouts()
    {
        for fault in 0..8 {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0887);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let mut graph = controller.enumerate_codec(0).unwrap();
            match fault {
                0 => graph.vendor_id = 0x10ec0256,
                1 => {
                    model.borrow_mut().parameters.insert((0, 0), 0x10ec0256);
                }
                2 => {
                    model.borrow_mut().parameters.insert((0, 2), 0x10001);
                }
                3 => {
                    model.borrow_mut().parameters.insert((0x20, 9), 1 << 6);
                }
                4 => {
                    model.borrow_mut().parameters.insert((1, 4), (2 << 16) | 6);
                }
                5 => {
                    model.borrow_mut().parameters.insert((1, 0x0f), 0);
                }
                6 => {
                    controller.reinitialize().unwrap();
                }
                7 => {
                    graph.groups[0].power_states = Some(0);
                }
                _ => unreachable!(),
            }
            let before = model.borrow().commands.len();
            assert!(controller.initialize_realtek_common(&graph).is_err());
            assert!(
                model.borrow().commands[before..]
                    .iter()
                    .all(|command| ((*command >> 16) & 15) >= 8)
            );
            assert!(model.borrow().coefficient_indexes.is_empty());
            assert!(!controller.routing_failed);
        }
    }

    #[test]
    fn realtek_common_running_and_uncertain_dma_refuse_before_verb_or_mmio_access() {
        for uncertain in [false, true] {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0887);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller.start(stream).unwrap();
            if uncertain {
                model.borrow_mut().stream_stop_stuck = true;
                assert!(matches!(
                    controller.stop(stream),
                    Err(Error::Timeout(Phase::StreamStop))
                ));
            }
            let before = access_counts(&model);
            assert_eq!(
                controller.initialize_realtek_common(&graph),
                Err(if uncertain {
                    Error::NeedsReset
                } else {
                    Error::StreamRunning
                })
            );
            assert_eq!(access_counts(&model), before);
        }
    }

    #[test]
    fn realtek_common_failed_power_index_coefficient_and_readback_poison_typed_start_until_reset() {
        for fault in 0..6 {
            let mut fixture = Fixture::new();
            let model = realtek_desktop_model(0x10ec0887);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let stream = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            match fault {
                0 => model.borrow_mut().coefficient_index_failed = true,
                1 => model.borrow_mut().coefficient_read_fault = Some(u32::MAX),
                2 => model.borrow_mut().coefficient_read_fault = Some(0x1ffff),
                3 => model.borrow_mut().reject_coefficient_write = true,
                4 => {
                    model.borrow_mut().coefficient_read_fault = Some(u32::MAX);
                    model.borrow_mut().coefficient_fault_after_write = true;
                }
                5 => model.borrow_mut().power_stuck = true,
                _ => unreachable!(),
            }
            assert_eq!(
                controller.initialize_realtek_common(&graph).unwrap_err(),
                if fault == 5 {
                    Error::Timeout(Phase::CodecPower)
                } else {
                    Error::CoefficientRejected {
                        node: 0x20,
                        index: 10,
                    }
                }
            );
            assert!(controller.routing_failed);
            assert_eq!(
                model.borrow().coefficient_writes,
                usize::from(fault == 3 || fault == 4)
            );
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(
                controller.initialize_realtek_common(&graph),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
            {
                let mut m = model.borrow_mut();
                m.coefficient_index_failed = false;
                m.coefficient_read_fault = None;
                m.reject_coefficient_write = false;
                m.power_stuck = false;
            }
            controller.reinitialize().unwrap();
            let fresh = controller.enumerate_codec(0).unwrap();
            controller.initialize_realtek_common(&fresh).unwrap();
        }
    }

    #[test]
    fn firmware_pin_candidates_are_real_format_checked_paths_without_electrical_inference() {
        let mut fixture = Fixture::new();
        let model = analog_model();
        model.borrow_mut().pin_defaults.insert(5, 0x01a1_9020);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        let output = graph
            .analog_endpoints(Direction::Playback, stereo())
            .unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].route.nodes(), &[4, 7, 6, 2]);
        assert_eq!(output[0].configuration.device(), PinDevice::LineOut);
        assert_eq!(output[0].configuration.connection(), PinConnection::Jack);
        assert_eq!(output[0].configuration.association(), 1);
        let input = graph
            .analog_endpoints(Direction::Capture, stereo())
            .unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].route.nodes(), &[3, 5]);
        assert_eq!(input[0].configuration.device(), PinDevice::Microphone);
        assert_eq!(input[0].configuration.color(), 9);
        assert_eq!(input[0].configuration.connector(), 1);
        assert_eq!(input[0].configuration.location(), 1);
        assert!(matches!(
            graph.analog_endpoints(
                Direction::Capture,
                PcmFormat {
                    rate: 192_000,
                    ..stereo()
                }
            ),
            Err(Error::UnsupportedTopology)
        ));
        assert_eq!(access_counts(&model), before);
        let mut changed = graph.clone();
        changed.groups[0]
            .widgets
            .iter_mut()
            .find(|widget| widget.node == 4)
            .unwrap()
            .pin_default = Some(0x4000_0000);
        assert!(matches!(
            changed.analog_endpoints(Direction::Playback, stereo()),
            Err(Error::UnsupportedTopology)
        ));
        let metadata = PinConfiguration { raw: u32::MAX };
        assert_eq!(metadata.device(), PinDevice::Other);
        assert_eq!(metadata.sequence(), 15);
        assert!(metadata.no_presence_detection());
    }

    #[test]
    fn polled_pin_sense_uses_real_verbs_trigger_and_full_width_measurement_without_routing_writes()
    {
        let mut fixture = Fixture::new();
        let model = analog_model();
        model.borrow_mut().parameters.insert((4, 0x0c), 0x1001f);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        for value in [0, 0x8000_0020, u32::MAX] {
            model.borrow_mut().pin_senses.insert(4, value);
            let sense = controller.poll_pin_sense(&graph, 4).unwrap();
            assert_eq!(sense.raw, value);
            assert_eq!(sense.present, value & (1 << 31) != 0);
            assert_eq!(
                sense.impedance_code,
                if value == u32::MAX {
                    None
                } else {
                    Some(value & 0x7fff_ffff)
                }
            );
        }
        let m = model.borrow();
        assert_eq!(m.sense_triggers, [4, 4, 4]);
        assert!(m.power_ready.is_empty());
        assert!(m.amplifiers.is_empty());
        assert_eq!(m.route_controls.len(), 1); //Only initial model EAPD, no routing.
        drop(m);
        let mut no_detect = graph.clone();
        no_detect.groups[0]
            .widgets
            .iter_mut()
            .find(|widget| widget.node == 4)
            .unwrap()
            .pin_default = Some(0x0101_4110);
        let before = access_counts(&model);
        assert_eq!(
            controller.poll_pin_sense(&no_detect, 4),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(access_counts(&model), before);
        controller.reinitialize().unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.poll_pin_sense(&graph, 4),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(access_counts(&model), before);
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
    #[test]
    fn local_rirb_status_acknowledgement_releases_response_counter_backpressure() {
        for enable_status in [true, false] {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            model.borrow_mut().response_backpressure = true;
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            assert_eq!(model.borrow().get(INTCTL, 4), 0);
            assert_eq!(model.borrow().bytes[RIRBCTL], RIRB_RUN_STATUS);
            if !enable_status {
                model.borrow_mut().bytes[RIRBCTL] = COMMAND_RUN;
            }
            assert_eq!(controller.verb(verb()).unwrap(), 0x1234_abcd);
            let result = controller.verb(verb());
            if enable_status {
                assert_eq!(result, Ok(0x1234_abcd));
                assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
                assert_eq!(model.borrow().response_count, 0);
                assert_eq!(model.borrow().commands.len(), 3);
            } else {
                assert_eq!(result, Err(Error::Timeout(Phase::Verb)));
                assert_eq!(model.borrow().commands.len(), 1);
            }
        }
    }
    #[test]
    fn all_ones_command_control_after_final_enable_refuses_constructor_and_attempts_cleanup() {
        for offset in [CORBCTL, RIRBCTL] {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            model.borrow_mut().command_start_read_failure = Some(offset);
            assert!(matches!(
                create(&model, &mut fixture, config()),
                Err(Error::Timeout(Phase::CommandStart))
            ));
            let m = model.borrow();
            assert!(m.command_started_once);
            assert_eq!(m.bytes[VMAJ], 1);
            assert!(m.commands.is_empty());
            assert_eq!(m.get(CORBWP, 2), 0);
            let enabled = m
                .writes
                .iter()
                .rposition(|(off, value, bytes)| {
                    *off == CORBCTL && *value == u32::from(COMMAND_RUN) && *bytes == 1
                })
                .unwrap();
            let cleanup = &m.writes[enabled + 1..];
            assert!(
                cleanup
                    .iter()
                    .any(|(off, value, bytes)| *off == CORBCTL && *value == 0 && *bytes == 1)
            );
            assert!(
                cleanup
                    .iter()
                    .any(|(off, value, bytes)| *off == RIRBCTL && *value == 0 && *bytes == 1)
            );
        }
    }
    #[test]
    fn control_read_failures_cannot_acknowledge_link_corb_or_codec_presence() {
        for case in 0..5 {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            let expected = {
                let mut m = model.borrow_mut();
                match case {
                    0 => {
                        m.control_read_failure = Some((GCTL, 4));
                        m.control_failure_active = true;
                        Error::RegisterUnavailable { offset: GCTL }
                    }
                    1 => {
                        m.control_read_failure = Some((GCTL, 4));
                        m.control_failure_after_write = Some((GCTL, GCTL_RESET, 4));
                        Error::Timeout(Phase::LinkResetExit)
                    }
                    2 => {
                        m.control_read_failure = Some((CORBRP, 2));
                        m.control_failure_after_write = Some((CORBRP, u32::from(POINTER_RESET), 2));
                        Error::Timeout(Phase::CorbResetEnter)
                    }
                    3 => {
                        m.control_read_failure = Some((STATESTS, 2));
                        m.control_failure_after_write = Some((GCTL, GCTL_RESET, 4));
                        Error::RegisterUnavailable { offset: STATESTS }
                    }
                    _ => {
                        m.control_read_failure = Some((CORBSIZE, 1));
                        m.control_failure_active = true;
                        Error::UnsupportedRingSize
                    }
                }
            };
            assert!(matches!(create(&model,&mut fixture,config()),Err(error) if error==expected));
            assert!(model.borrow().commands.is_empty());
            if case == 0 {
                assert!(
                    !model
                        .borrow()
                        .writes
                        .iter()
                        .any(|(offset, _, _)| *offset == GCTL)
                );
            }
        }
    }

    #[test]
    fn failed_stream_control_reads_refuse_reset_start_and_stop_without_cpu_buffer_ownership() {
        for case in 0..4 {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let base = stream_base(controller.capabilities.input_streams);
            if case == 0 {
                {
                    let mut m = model.borrow_mut();
                    m.control_read_failure = Some((base + SD_CTL, 1));
                    m.control_failure_after_write = Some((base + SD_CTL, u32::from(SD_RESET), 1));
                }
                assert_eq!(
                    controller.allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator
                    ),
                    Err(Error::Timeout(Phase::StreamResetEnter))
                );
                continue;
            }
            let id = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            if case == 1 {
                {
                    let mut m = model.borrow_mut();
                    m.control_read_failure = Some((base + SD_CTL, 1));
                    m.control_failure_after_write = Some((base + SD_CTL, u32::from(SD_RUN), 1));
                }
                assert_eq!(
                    controller.start(id),
                    Err(Error::Timeout(Phase::StreamStart))
                );
            } else {
                controller.start(id).unwrap();
                let before = model.borrow().writes.len();
                {
                    let mut m = model.borrow_mut();
                    m.control_read_failure = Some((base + SD_CTL, 1));
                    if case == 2 {
                        m.control_failure_active = true;
                    } else {
                        m.control_failure_after_write = Some((base + SD_CTL, 0, 1));
                    }
                }
                assert_eq!(
                    controller.stop(id),
                    Err(if case == 2 {
                        Error::RegisterUnavailable {
                            offset: base + SD_CTL,
                        }
                    } else {
                        Error::Timeout(Phase::StreamStop)
                    })
                );
                if case == 2 {
                    assert_eq!(model.borrow().writes.len(), before);
                }
            }
            assert_eq!(controller.write_pcm(id, 0, &[1]), Err(Error::NeedsReset));
        }
    }

    #[test]
    fn converter_binding_ff_is_valid_data_but_full_failed_response_is_rejected() {
        for failed_read in [false, true] {
            let mut fixture = Fixture::new();
            let model = graph_model();
            model.borrow_mut().set(GCAP, (15 << 12) | 1, 2);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let mut graph = controller.enumerate_codec(0).unwrap();
            graph.groups[0]
                .widgets
                .iter_mut()
                .find(|widget| widget.node == 2)
                .unwrap()
                .capabilities &= !1;
            let small = PcmFormat {
                rate: 8_000,
                bits: 8,
                channels: 1,
            };
            for _ in 0..14 {
                controller
                    .allocate_stream(Direction::Playback, small, 128, 2, &mut fixture.allocator)
                    .unwrap();
            }
            let id = controller
                .allocate_stream(
                    Direction::Playback,
                    PcmFormat {
                        channels: 16,
                        ..stereo()
                    },
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            assert_eq!(id.tag(), 15);
            model.borrow_mut().binding_read_failure = failed_read;
            let result = controller.bind_converter(&graph, 2, id, 15);
            assert_eq!(
                result,
                if failed_read {
                    Err(Error::ConverterRejected)
                } else {
                    Ok(())
                }
            );
            assert_eq!(model.borrow().bindings[&2], 0xff);
        }
    }
    #[test]
    fn dma_identity_ceiling_checks_full_32_40_and_64_bit_extents() {
        for bits in [32, 40, 48] {
            let limit = 1u64 << bits;
            assert_eq!(check_dma_range(limit - 4096, 4096, 4096, bits), Ok(()));
            assert_eq!(
                check_dma_range(limit - 4096, 4097, 4096, bits),
                Err(Error::DmaAddress)
            );
            assert_eq!(
                check_dma_range(limit, 4096, 4096, bits),
                Err(Error::DmaAddress)
            );
            assert_eq!(check_dma_range(limit - 4096, 4096, 4096, 64), Ok(()));
        }
        assert_eq!(check_dma_range(0, 4096, 4096, 64), Err(Error::DmaAddress));
        assert_eq!(
            check_dma_range(4097, 4096, 4096, 64),
            Err(Error::DmaAddress)
        );
        assert_eq!(
            check_dma_range(u64::MAX - 4095, 4096, 4096, 64),
            Err(Error::DmaAddress)
        );
    }

    #[test]
    fn configured_dma_ceiling_is_explicit_and_applies_to_rings_before_hardware_writes() {
        for bits in [0, 31, 65, u8::MAX] {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            assert!(matches!(
                create(
                    &model,
                    &mut fixture,
                    Config {
                        dma_address_bits: bits,
                        ..config()
                    }
                ),
                Err(Error::InvalidConfiguration)
            ));
            assert!(model.borrow().writes.is_empty());
        }
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let mut controller = create(
            &model,
            &mut fixture,
            Config {
                dma_address_bits: 48,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(controller.capabilities().dma_address_bits, 48);
        controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller.shutdown().unwrap();
        // A valid allocator's CPU address can exceed a controller's identity
        // width even when GCAP advertises 64-bit addressing. Never start DMA.
        let next = fixture.allocator.allocate(128, 128).unwrap();
        if next.physical() >= 1u64 << 40 {
            let mut fixture = Fixture::new();
            let model = Model::new(256);
            assert!(matches!(
                create(
                    &model,
                    &mut fixture,
                    Config {
                        dma_address_bits: 40,
                        ..config()
                    }
                ),
                Err(Error::DmaAddress)
            ));
            assert!(model.borrow().writes.is_empty());
        }
    }
    #[test]
    fn independent_direction_tags_cover_all_thirty_descriptors_without_aliasing_buffers_or_handles()
    {
        for policy in [StreamTagPolicy::Global, StreamTagPolicy::PerDirection] {
            let mut fixture = Fixture::new();
            let model = Model::new(16);
            model.borrow_mut().set(GCAP, 0xff01, 2); //15capture+15playback,64bitDMA.
            model.borrow_mut().set(INPAY, 100, 2);
            model.borrow_mut().set(OUTPAY, 100, 2);
            let mut controller = create(
                &model,
                &mut fixture,
                Config {
                    stream_tag_policy: policy,
                    ..config()
                },
            )
            .unwrap();
            let mut capture = Vec::new();
            for tag in 1..=15 {
                let id = controller
                    .allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator)
                    .unwrap();
                assert_eq!(id.tag(), tag);
                assert_eq!(id.descriptor_index(), tag - 1);
                capture.push(id);
            }
            if policy == StreamTagPolicy::Global {
                let before = access_counts(&model);
                let remaining = fixture.allocator.remaining();
                assert_eq!(
                    controller.allocate_stream(
                        Direction::Playback,
                        pcm(),
                        128,
                        2,
                        &mut fixture.allocator
                    ),
                    Err(Error::NoStream)
                );
                assert_eq!(access_counts(&model), before);
                assert_eq!(fixture.allocator.remaining(), remaining);
                continue;
            }
            let mut playback = Vec::new();
            for tag in 1..=15 {
                let id = controller
                    .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
                    .unwrap();
                assert_eq!(id.tag(), tag);
                assert_eq!(id.descriptor_index(), 14 + tag);
                assert_ne!(id, capture[usize::from(tag - 1)]);
                let control = model
                    .borrow()
                    .get(stream_base(id.descriptor_index()) + SD_CTL + 2, 1);
                assert_eq!(control >> 4, u32::from(tag));
                playback.push(id);
            }
            assert_eq!(
                controller.allocate_stream(
                    Direction::Capture,
                    pcm(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::NoStream)
            );
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    pcm(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::NoStream)
            );
            controller.fill_capture(capture[0], 0xa5).unwrap();
            controller.write_pcm(playback[0], 0, &[0x5a; 256]).unwrap();
            let mut bytes = [0; 256];
            controller.read_pcm(capture[0], 0, &mut bytes).unwrap();
            assert_eq!(bytes, [0xa5; 256]);
            controller.start(capture[0]).unwrap();
            controller.start(playback[0]).unwrap();
            assert_eq!(
                model
                    .borrow()
                    .get(stream_base(capture[0].descriptor_index()) + SD_CTL, 1)
                    & u32::from(SD_RUN),
                u32::from(SD_RUN)
            );
            assert_eq!(
                model
                    .borrow()
                    .get(stream_base(playback[0].descriptor_index()) + SD_CTL, 1)
                    & u32::from(SD_RUN),
                u32::from(SD_RUN)
            );
        }
    }

    #[test]
    fn amd_fifo_capture_correction_keeps_exact_transport_and_wrap_coordinates() {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let mut controller = create(
            &model,
            &mut fixture,
            Config {
                position_policy: PositionPolicy::AmdFifo32,
                ..config()
            },
        )
        .unwrap();
        let capture = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        let base = stream_base(capture.descriptor_index());
        for (raw, pcm, delay, frames) in [
            (0, 0, 0, 0),
            (5, 0, 5, 1),
            (127, 0, 127, 31),
            (128, 0, 128, 32),
            (200, 72, 128, 32),
            (10, 138, 128, 32),
            (256, 128, 128, 32),
        ] {
            model.borrow_mut().set(base + SD_LPIB, raw, 4);
            let info = controller.position_info(capture).unwrap();
            assert_eq!(
                info,
                PositionInfo {
                    raw_link_bytes: raw,
                    transport_bytes: if raw == 256 { 0 } else { raw },
                    pcm_bytes: pcm,
                    fifo_delay_bytes: delay,
                    fifo_delay_frames: frames
                }
            );
            assert_eq!(controller.link_position(capture).unwrap(), raw);
            assert_eq!(controller.position(capture).unwrap(), info.transport_bytes);
            let status = controller.status(capture).unwrap();
            assert_eq!(status.position_bytes, info.transport_bytes);
            assert_eq!(status.position.pcm_bytes, pcm);
        }
        model.borrow_mut().set(base + SD_LPIB, 257, 4);
        assert_eq!(
            controller.position_info(capture),
            Err(Error::InvalidPosition(257))
        );
    }

    #[test]
    fn amd_fifo_playback_reports_delay_without_inventing_position_and_restart_clamps_again() {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let mut controller = create(
            &model,
            &mut fixture,
            Config {
                position_policy: PositionPolicy::AmdFifo32,
                ..config()
            },
        )
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
        let capture = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        let pbase = stream_base(playback.descriptor_index());
        let cbase = stream_base(capture.descriptor_index());
        model.borrow_mut().set(pbase + SD_LPIB, 5, 4);
        let info = controller.position_info(playback).unwrap();
        assert_eq!(
            (info.transport_bytes, info.pcm_bytes, info.fifo_delay_bytes),
            (5, 5, 5)
        );
        model.borrow_mut().set(pbase + SD_LPIB, 128, 4);
        let info = controller.position_info(playback).unwrap();
        assert_eq!(
            (info.transport_bytes, info.pcm_bytes, info.fifo_delay_frames),
            (128, 128, 32)
        );
        controller.start(capture).unwrap();
        model.borrow_mut().set(cbase + SD_LPIB, 200, 4);
        assert_eq!(controller.position_info(capture).unwrap().pcm_bytes, 72);
        controller.stop(capture).unwrap();
        model.borrow_mut().set(cbase + SD_LPIB, 0, 4);
        controller.start(capture).unwrap();
        model.borrow_mut().set(cbase + SD_LPIB, 5, 4);
        let info = controller.position_info(capture).unwrap();
        assert_eq!(
            (info.transport_bytes, info.pcm_bytes, info.fifo_delay_bytes),
            (5, 0, 5)
        );
        controller.stop(capture).unwrap();
    }

    #[test]
    fn amd_fifo_inclusive_first_endpoint_is_primed_and_small_rings_refuse_before_allocating() {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let mut controller = create(
            &model,
            &mut fixture,
            Config {
                position_policy: PositionPolicy::AmdFifo32,
                ..config()
            },
        )
        .unwrap();
        let capture = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        model
            .borrow_mut()
            .set(stream_base(capture.descriptor_index()) + SD_LPIB, 256, 4);
        let info = controller.position_info(capture).unwrap();
        assert_eq!(
            (
                info.raw_link_bytes,
                info.transport_bytes,
                info.pcm_bytes,
                info.fifo_delay_bytes
            ),
            (256, 0, 128, 128)
        );
        let before = fixture.allocator.remaining();
        let writes = model.borrow().writes.len();
        let wide = PcmFormat {
            channels: 16,
            ..stereo()
        };
        assert_eq!(
            controller.allocate_stream(Direction::Playback, wide, 512, 2, &mut fixture.allocator),
            Err(Error::InvalidBuffer)
        );
        assert_eq!(fixture.allocator.remaining(), before);
        assert_eq!(model.borrow().writes.len(), writes);
        controller
            .allocate_stream(Direction::Playback, wide, 640, 2, &mut fixture.allocator)
            .unwrap();
    }
    mod conexant {
        use super::*;

        fn device(id: u32, eapds: usize) -> Rc<RefCell<Model>> {
            let model = analog_model();
            let mut m = model.borrow_mut();
            m.parameters.insert((0, 0), id);
            // Seven base widgets plus extra disconnected pins. EAPD enumeration must
            // include firmware-disconnected pins, just as cx_auto_parse_eapd does.
            m.parameters.insert((1, 4), (2 << 16) | 9);
            m.parameters.insert((4, 0x0c), 0x18);
            m.parameters.insert((4, 0x0e), 2);
            m.connection_words.insert((4, 0), 3 | (7 << 8));
            m.parameters.insert((3, 0x0e), 2);
            m.connection_words.insert((3, 0), 4 | (5 << 8));
            for node in 8..=10 {
                m.parameters.insert((node, 9), 4 << 20);
                m.parameters.insert((node, 0x0c), 0x10);
                m.pin_defaults.insert(node, 1 << 30);
            }
            for node in [4, 5, 8, 9, 10].into_iter().take(eapds) {
                *m.parameters.get_mut(&(node, 0x0c)).unwrap() |= 1 << 16;
                m.route_controls.insert((node, 0xf0c), 5);
            }
            drop(m);
            model
        }

        fn playback_options() -> PinOptions {
            PinOptions::Playback {
                headphone: true,
                eapd: None,
            }
        }

        #[test]
        fn conexant_live_eapd_inventory_uses_actual_pin_count_and_whole_global_value() {
            for count in 0..=4 {
                let mut fixture = Fixture::new();
                let model = device(0x14f1_5098, count);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let report = controller.initialize_conexant_codec(&graph).unwrap();
                assert_eq!(report.codec_id, 0x14f1_5098);
                assert_eq!(report.revision_id, 0x0010_0100);
                assert_eq!(report.subsystem_id, 0x1043_8693);
                assert_eq!(report.function_group, 1);
                assert!(!report.single_adc_amplifier);
                assert_eq!(report.eapd.len(), count);
                let expected = if count > 2 {
                    ConexantEapdMode::Dynamic
                } else {
                    ConexantEapdMode::Global
                };
                assert_eq!(report.eapd_mode, expected);
                for (_, value) in &report.eapd {
                    assert_eq!(*value, if count > 2 { 5 } else { 2 });
                }
                let before = access_counts(&model);
                assert_eq!(
                    controller.initialize_conexant_codec(&graph),
                    Err(Error::RouteInUse)
                );
                assert_eq!(access_counts(&model), before);
                controller
                    .set_conexant_outputs_enabled(&graph, false)
                    .unwrap();
                for (node, _) in &report.eapd {
                    assert_eq!(model.borrow().route_controls[&(*node, 0xf0c)], 0);
                }
                controller
                    .set_conexant_outputs_enabled(&graph, true)
                    .unwrap();
                controller.shutdown().unwrap();
                for (node, _) in report.eapd {
                    assert_eq!(model.borrow().route_controls[&(node, 0xf0c)], 0);
                }
            }
        }

        #[test]
        fn conexant_selected_adc_and_pin_connections_use_correct_amp_indices_and_pcm() {
            for codec in [0x14f1_5045, 0x14f1_5047, 0x14f1_5098] {
                let mut fixture = Fixture::new();
                let model = device(codec, 3);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let report = controller.initialize_conexant_codec(&graph).unwrap();
                assert_eq!(report.single_adc_amplifier, codec == 0x14f1_5045);
                let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
                let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
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
                    .configure_conexant_route(&graph, &output, playback, 0, playback_options())
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
                {
                    let m = model.borrow();
                    assert_eq!(m.route_controls[&(3, 0xf01)], 1);
                    assert_eq!(m.route_controls[&(4, 0xf01)], 1);
                    for channel in 0..2 {
                        assert_eq!(m.amplifiers[&(4, true, 0, channel)], 0x1f);
                        assert!(!m.amplifiers.contains_key(&(4, true, 1, channel)));
                        let index = u8::from(codec != 0x14f1_5045);
                        assert_eq!(m.amplifiers[&(3, false, index, channel)], 0x1f);
                        assert!(!m.amplifiers.contains_key(&(3, false, 1 - index, channel)));
                    }
                }
                // Dynamic initialization and analog routing do not own EAPD policy.
                assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5);
                controller
                    .set_conexant_outputs_enabled(&graph, true)
                    .unwrap();
                assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
                controller.write_pcm(playback, 0, &[0x5a; 256]).unwrap();
                controller.fill_capture(capture, 0xa5).unwrap();
                controller.start(capture).unwrap();
                controller.start(playback).unwrap();
                controller
                    .set_conexant_outputs_enabled(&graph, false)
                    .unwrap();
                assert!(controller.status(playback).unwrap().running);
                controller
                    .set_conexant_outputs_enabled(&graph, true)
                    .unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 16);
                assert!(controller.status(playback).unwrap().period_completed);
                assert!(controller.status(capture).unwrap().period_completed);
                controller.stop(capture).unwrap();
                let mut actual = [0; 256];
                controller.read_pcm(capture, 0, &mut actual).unwrap();
                assert_eq!(actual, core::array::from_fn(|index| index as u8));
                controller.shutdown().unwrap();
                let m = model.borrow();
                assert!(m.playback.len() >= 256);
                assert!(m.playback.iter().all(|byte| *byte == 0x5a));
                for node in [4, 5, 8] {
                    assert_eq!(m.route_controls[&(node, 0xf0c)], 0);
                }
                assert_eq!(
                    m.get(stream_base(playback.descriptor_index()) + SD_CTL, 1) & u32::from(SD_RUN),
                    0
                );
                assert_eq!(m.get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
            }
        }

        #[test]
        fn conexant_refuses_stale_live_metadata_and_unsupported_headsets_before_effects() {
            for case in 0..9 {
                let mut fixture = Fixture::new();
                let model = device(
                    if case == 0 { 0x14f1_1f86 } else { 0x14f1_5047 },
                    if case == 1 { 5 } else { 3 },
                );
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                {
                    let mut m = model.borrow_mut();
                    match case {
                        2 => {
                            m.parameters.insert((0, 0), 0x14f1_5098);
                        }
                        3 => {
                            m.parameters.insert((0, 2), u32::MAX);
                        }
                        4 => {
                            m.parameters.insert((0, 4), (2 << 16) | 1);
                        }
                        5 => {
                            m.parameters.insert((1, 5), 2);
                        }
                        6 => {
                            m.parameters.insert((1, 4), (2 << 16) | 8);
                        }
                        7 => {
                            m.parameters.insert((2, 9), 4 << 20);
                        }
                        8 => {
                            m.parameters.insert((8, 0x0c), u32::MAX);
                        }
                        _ => (),
                    }
                }
                let before = model.borrow().commands.len();
                assert!(controller.initialize_conexant_codec(&graph).is_err());
                assert!(controller.conexant_codecs.is_empty());
                let m = model.borrow();
                assert!(
                    m.commands[before..]
                        .iter()
                        .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
                );
            }
        }

        #[test]
        fn conexant_bad_route_options_are_pure_preflight_and_initialized_identity_is_live() {
            let mut fixture = Fixture::new();
            let model = device(0x14f1_5098, 3);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
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
            for eapd in [Some(true), Some(false)] {
                let before = model.borrow().commands.len();
                assert_eq!(
                    controller.configure_analog_route(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd
                        }
                    ),
                    Err(Error::InvalidPinControl)
                );
                assert!(
                    model.borrow().commands[before..]
                        .iter()
                        .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
                );
                assert!(!controller.routing_failed);
            }
            model.borrow_mut().parameters.insert((8, 0x0c), 0x10);
            assert_eq!(
                controller.set_conexant_outputs_enabled(&graph, true),
                Err(Error::InvalidCodecGraph)
            );
            assert!(controller.routes.is_empty());
        }

        #[test]
        fn conexant_partial_init_master_and_route_failures_hold_state_until_actual_reset() {
            for case in 0..4 {
                let mut fixture = Fixture::new();
                let model = device(0x14f1_5045, if case == 0 { 2 } else { 3 });
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
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
                if case == 0 {
                    let mut m = model.borrow_mut();
                    m.reject_route_control = Some(0xf0c);
                    m.reject_route_node = Some(5);
                } else if case == 1 {
                    model.borrow_mut().reject_route_control = Some(0xf0c);
                }
                if case < 2 {
                    assert_eq!(
                        controller.initialize_conexant_codec(&graph),
                        Err(Error::RouteRejected)
                    );
                } else {
                    controller.initialize_conexant_codec(&graph).unwrap();
                    if case == 2 {
                        model.borrow_mut().reject_route_control = Some(0xf0c);
                        assert_eq!(
                            controller.set_conexant_outputs_enabled(&graph, true),
                            Err(Error::RouteRejected)
                        );
                    } else {
                        model.borrow_mut().reject_amplifier = true;
                        assert_eq!(
                            controller.configure_conexant_route(
                                &graph,
                                &route,
                                stream,
                                0,
                                playback_options()
                            ),
                            Err(Error::RouteRejected)
                        );
                    }
                }
                assert_eq!(controller.conexant_codecs.len(), 1);
                let before = access_counts(&model);
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
                model.borrow_mut().reject_route_control = None;
                model.borrow_mut().reject_amplifier = false;
                controller.reinitialize().unwrap();
                assert!(controller.conexant_codecs.is_empty());
                let before = access_counts(&model);
                assert_eq!(
                    controller.initialize_conexant_codec(&graph),
                    Err(Error::InvalidCodecGraph)
                );
                assert_eq!(access_counts(&model), before);
            }
        }

        #[test]
        fn conexant_shutdown_faults_keep_amplifier_ownership_and_require_reset() {
            for case in 0..3 {
                let mut fixture = Fixture::new();
                let model = device(0x14f1_5098, 3);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller.initialize_conexant_codec(&graph).unwrap();
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
                controller
                    .configure_conexant_route(&graph, &route, stream, 0, playback_options())
                    .unwrap();
                controller.start(stream).unwrap();
                let before = model.borrow().commands.len();
                {
                    let mut m = model.borrow_mut();
                    match case {
                        0 => m.stream_stop_stuck = true,
                        1 => m.command_stop_stuck = true,
                        _ => {
                            m.reject_route_control = Some(0xf0c);
                            m.reject_route_node = Some(5);
                        }
                    }
                }
                assert!(controller.shutdown().is_err());
                assert_eq!(controller.conexant_codecs.len(), 1);
                assert_eq!(controller.routes.len(), 1);
                if case == 0 {
                    assert!(model.borrow().commands[before..].is_empty());
                    assert!(!controller.stopped);
                } else if case == 2 {
                    assert!(controller.stopped);
                }
                {
                    let mut m = model.borrow_mut();
                    m.stream_stop_stuck = false;
                    m.command_stop_stuck = false;
                    m.reject_route_control = None;
                }
                controller.reinitialize().unwrap();
                assert!(controller.conexant_codecs.is_empty());
                assert!(controller.routes.is_empty());
            }
        }
        #[test]
        fn conexant_direct_reset_turns_amplifiers_off_before_releasing_the_old_generation() {
            let mut fixture = Fixture::new();
            let model = device(0x14f1_5047, 2);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
            assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
            controller.reinitialize().unwrap();
            for node in [4, 5] {
                assert_eq!(model.borrow().route_controls[&(node, 0xf0c)], 0);
            }
            assert!(controller.conexant_codecs.is_empty());
            let before = access_counts(&model);
            assert_eq!(
                controller.set_conexant_outputs_enabled(&graph, true),
                Err(Error::InvalidCodecGraph)
            );
            assert_eq!(access_counts(&model), before);
        }

        #[test]
        fn conexant_initial_power_failure_and_lost_master_reply_quarantine_real_effects() {
            for power_fault in [true, false] {
                let mut fixture = Fixture::new();
                let model = device(0x14f1_5098, 3);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                if power_fault {
                    model.borrow_mut().power_stuck = true;
                    assert_eq!(
                        controller.initialize_conexant_codec(&graph),
                        Err(Error::Timeout(crate::audio::Phase::CodecPower))
                    );
                    assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5);
                } else {
                    controller.initialize_conexant_codec(&graph).unwrap();
                    // The master's first SET may take effect, but its response
                    // is lost. Never treat the unchanged software state as proof
                    // that hardware was untouched or send another unsafe verb.
                    model.borrow_mut().drop_reply_command =
                        Some(Verb::short(0, 4, 0x70c, 2).unwrap().raw());
                    assert_eq!(
                        controller.set_conexant_outputs_enabled(&graph, true),
                        Err(Error::Timeout(crate::audio::Phase::Verb))
                    );
                    assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
                    assert!(controller.command_poisoned);
                }
                assert_eq!(controller.conexant_codecs.len(), 1);
                let before = access_counts(&model);
                assert_eq!(
                    controller.set_conexant_outputs_enabled(&graph, true),
                    Err(Error::NeedsReset)
                );
                assert_eq!(access_counts(&model), before);
                {
                    let mut m = model.borrow_mut();
                    m.power_stuck = false;
                    m.drop_reply_command = None;
                }
                controller.reinitialize().unwrap();
                assert!(controller.conexant_codecs.is_empty());
            }
        }
        #[test]
        fn conexant_failed_command_restart_cannot_reuse_stale_shutdown_acknowledgements() {
            let mut fixture = Fixture::new();
            let model = device(0x14f1_5098, 3);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
            controller.shutdown().unwrap();
            assert!(controller.stopped);
            {
                let mut m = model.borrow_mut();
                // Initial stop is still acknowledged. Only the later restart
                // produces unreadable RUN controls and rejects cleanup stops.
                m.command_started_once = false;
                m.command_start_read_failure = Some(CORBCTL);
                m.command_stop_stuck = true;
            }
            assert_eq!(
                controller.reinitialize(),
                Err(Error::Timeout(crate::audio::Phase::CommandStart))
            );
            assert!(!controller.stopped);
            let token = controller.token;
            assert_eq!(
                controller.reinitialize(),
                Err(Error::Timeout(crate::audio::Phase::CommandStop))
            );
            assert_eq!(controller.token, token);
            assert_eq!(controller.conexant_codecs.len(), 1);
            {
                let mut m = model.borrow_mut();
                m.command_start_read_failure = None;
                m.command_stop_stuck = false;
            }
            controller.reinitialize().unwrap();
            assert!(controller.conexant_codecs.is_empty());
        }
        #[test]
        fn conexant_lost_owned_live_authority_blocks_previous_routes_from_starting() {
            for master_call in [true, false] {
                for changed_vendor in [true, false] {
                    let mut fixture = Fixture::new();
                    let model = device(0x14f1_5045, 3);
                    let mut controller = create(&model, &mut fixture, config()).unwrap();
                    let graph = controller.enumerate_codec(0).unwrap();
                    controller.initialize_conexant_codec(&graph).unwrap();
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
                    controller
                        .configure_analog_route(&graph, &route, playback, 0, playback_options())
                        .unwrap();
                    let capture = controller
                        .allocate_stream(
                            Direction::Capture,
                            stereo(),
                            128,
                            2,
                            &mut fixture.allocator,
                        )
                        .unwrap();
                    let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
                    if changed_vendor {
                        model.borrow_mut().parameters.insert((0, 0), 0x14f1_5098);
                    } else {
                        model.borrow_mut().parameters.insert((8, 0x0c), 0x10);
                    }
                    let before = model.borrow().commands.len();
                    let result = if master_call {
                        controller.set_conexant_outputs_enabled(&graph, true)
                    } else {
                        controller.configure_analog_route(
                            &graph,
                            &input,
                            capture,
                            0,
                            PinOptions::Capture {
                                vref: Vref::EightyPercent,
                            },
                        )
                    };
                    assert_eq!(result, Err(Error::InvalidCodecGraph));
                    assert!(
                        model.borrow().commands[before..]
                            .iter()
                            .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
                    );
                    let before = access_counts(&model);
                    assert_eq!(controller.start(playback), Err(Error::NeedsReset));
                    assert_eq!(controller.start(capture), Err(Error::NeedsReset));
                    assert_eq!(access_counts(&model), before);
                    assert_eq!(controller.routes.len(), 1);
                    assert_eq!(controller.conexant_codecs.len(), 1);
                    let before = model.borrow().commands.len();
                    assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
                    assert!(controller.stopped);
                    assert_eq!(model.borrow().commands.len(), before);
                }
            }
        }
        fn headset_device(id: u32, present: bool) -> Rc<RefCell<Model>> {
            let model = device(id, 3);
            let mut m = model.borrow_mut();
            m.conexant_headset_model = true;
            m.conexant_detection_ready = Some(0);
            m.conexant_type = 0x800;
            m.parameters.insert((1, 4), (2 << 16) | 27);
            for node in 11..=0x1c {
                m.parameters.insert((node, 9), 0);
            }
            m.parameters.insert((0x16, 9), (4 << 20) | 1 | (1 << 8));
            m.parameters.insert((0x16, 0x0c), 0x18);
            m.parameters.insert((0x16, 0x0e), 1);
            m.connection_words.insert((0x16, 0), 2);
            m.parameters.insert((0x19, 9), (4 << 20) | 1 | (1 << 1));
            m.parameters.insert((0x19, 0x0c), 0x1124);
            m.parameters.insert((0x1c, 9), 0xf << 20);
            m.connection_words.insert((3, 0), 0x19);
            m.parameters.insert((3, 0x0e), 1);
            m.pin_senses.insert(0x19, if present { 1 << 31 } else { 0 });
            drop(m);
            model
        }

        #[test]
        fn conexant_headset_cold_trim_bias_real_routes_and_duplex_pcm() {
            for id in [0x14f1_1f86, 0x14f1_1f87] {
                for present in [false, true] {
                    let mut fixture = Fixture::new();
                    let model = headset_device(id, present);
                    let mut controller = create(&model, &mut fixture, config()).unwrap();
                    let graph = controller.enumerate_codec(0).unwrap();
                    assert_eq!(
                        controller.initialize_conexant_codec(&graph),
                        Err(Error::UnsupportedTopology)
                    );
                    let report = controller
                        .initialize_conexant_headset_codec(&graph)
                        .unwrap();
                    assert_eq!(model.borrow().conexant_trim, Some(0xe10));
                    assert_eq!(
                        report.headset.kind,
                        if present {
                            ConexantHeadsetKind::Unclassified
                        } else {
                            ConexantHeadsetKind::Disconnected
                        }
                    );
                    assert_eq!(
                        report.headset.microphone_control,
                        if present { 0x24 } else { 0x20 }
                    );
                    let m = model.borrow();
                    assert!(m.commands.contains(&((0x1c << 20) | 0x3be10)));
                    assert_eq!(m.conexant_detection_reads, 0);
                    drop(m);
                    let output = graph.analog_route(Direction::Playback, 0x16, 2).unwrap();
                    let input = graph.analog_route(Direction::Capture, 0x19, 3).unwrap();
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
                        .allocate_stream(
                            Direction::Capture,
                            stereo(),
                            128,
                            2,
                            &mut fixture.allocator,
                        )
                        .unwrap();
                    assert_eq!(
                        controller.configure_analog_route(
                            &graph,
                            &output,
                            playback,
                            0,
                            PinOptions::Playback {
                                headphone: false,
                                eapd: None
                            }
                        ),
                        Err(Error::InvalidPinControl)
                    );
                    controller
                        .configure_analog_route(
                            &graph,
                            &output,
                            playback,
                            0,
                            PinOptions::Playback {
                                headphone: true,
                                eapd: None,
                            },
                        )
                        .unwrap();
                    let vref = if present {
                        Vref::EightyPercent
                    } else {
                        Vref::HighImpedance
                    };
                    let wrong = if present {
                        Vref::HighImpedance
                    } else {
                        Vref::EightyPercent
                    };
                    assert_eq!(
                        controller.configure_analog_route(
                            &graph,
                            &input,
                            capture,
                            0,
                            PinOptions::Capture { vref: wrong }
                        ),
                        Err(Error::InvalidPinControl)
                    );
                    assert!(!controller.routing_failed);
                    controller
                        .configure_analog_route(
                            &graph,
                            &input,
                            capture,
                            0,
                            PinOptions::Capture { vref },
                        )
                        .unwrap();
                    controller
                        .set_conexant_outputs_enabled(&graph, true)
                        .unwrap();
                    controller.write_pcm(playback, 0, &[0x39; 256]).unwrap();
                    controller.fill_capture(capture, 0xa5).unwrap();
                    controller.start(capture).unwrap();
                    controller.start(playback).unwrap();
                    model.borrow_mut().dma_step_bytes = 128;
                    advance(&model, 16);
                    assert!(controller.status(playback).unwrap().period_completed);
                    assert!(controller.status(capture).unwrap().period_completed);
                    model
                        .borrow_mut()
                        .pin_senses
                        .insert(0x19, if present { 0 } else { 1 << 31 });
                    let changed = controller.poll_conexant_headset(&graph).unwrap();
                    assert_eq!(
                        changed.microphone_control,
                        if present { 0x20 } else { 0x24 }
                    );
                    assert!(controller.status(capture).unwrap().running);
                    controller.stop(capture).unwrap();
                    let mut actual = [0; 256];
                    controller.read_pcm(capture, 0, &mut actual).unwrap();
                    assert_eq!(actual, core::array::from_fn(|index| index as u8));
                    controller.shutdown().unwrap();
                    assert!(model.borrow().playback.iter().all(|byte| *byte == 0x39));
                    assert!(model.borrow().playback.len() >= 256);
                }
            }
        }

        #[test]
        fn conexant_headset_poll_preserves_type_precedence_and_source_bias_on_headphone_only() {
            for (raw, kind) in [
                (0, ConexantHeadsetKind::Headphone),
                (0x400, ConexantHeadsetKind::Omtp),
                (0x800, ConexantHeadsetKind::Ctia),
                (0xc00, ConexantHeadsetKind::Ctia),
            ] {
                let mut fixture = Fixture::new();
                let model = headset_device(0x14f1_1f87, false);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller
                    .initialize_conexant_headset_codec(&graph)
                    .unwrap();
                {
                    let mut m = model.borrow_mut();
                    m.pin_senses.insert(0x19, 0x8000_005a);
                    m.conexant_type = raw;
                    m.conexant_detection_ready = Some(m.clock.now_us() + 25_000);
                }
                let writes_before = model.borrow().conexant_mic_writes;
                let before = model.borrow().clock.now_us();
                let report = controller.poll_conexant_headset(&graph).unwrap();
                assert_eq!(report.kind, kind);
                assert_eq!(
                    model.borrow().conexant_mic_writes - writes_before,
                    if raw == 0 { 1 } else { 2 }
                );
                assert_eq!(report.sense, 0x8000_005a);
                assert_eq!(report.detection_status, Some(0x80));
                assert_eq!(report.type_status, Some(raw));
                assert_eq!(report.microphone_control, 0x24);
                assert_eq!(model.borrow().conexant_detection_reads, 3);
                assert!(model.borrow().clock.now_us() - before >= 40_000);
                let before = model.borrow().conexant_detection_reads;
                model.borrow_mut().pin_senses.insert(0x19, 0);
                let report = controller.poll_conexant_headset(&graph).unwrap();
                assert_eq!(report.kind, ConexantHeadsetKind::Disconnected);
                assert_eq!(report.microphone_control, 0x20);
                assert_eq!(model.borrow().conexant_detection_reads, before);
            }
        }

        #[test]
        fn conexant_headset_incomplete_detection_and_readback_failures_hold_owned_routes() {
            for fault in 0..6 {
                let mut fixture = Fixture::new();
                let model = headset_device(0x14f1_1f86, true);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller
                    .initialize_conexant_headset_codec(&graph)
                    .unwrap();
                let route = graph.analog_route(Direction::Capture, 0x19, 3).unwrap();
                let stream = controller
                    .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                    .unwrap();
                controller
                    .configure_analog_route(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Capture {
                            vref: Vref::EightyPercent,
                        },
                    )
                    .unwrap();
                {
                    let mut m = model.borrow_mut();
                    match fault {
                        0 => m.conexant_detection_ready = None,
                        1 => m.conexant_vendor_fault = Some(0xca0),
                        2 => m.conexant_vendor_fault = Some(0xcb0),
                        3 => {
                            m.reject_route_control = Some(0xf07);
                            m.reject_route_node = Some(0x19);
                        }
                        4 => {
                            m.pin_senses.insert(0x19, u32::MAX);
                        }
                        _ => {
                            m.conexant_mic_fault_after = Some(m.conexant_mic_writes + 2);
                        }
                    }
                }
                let before = model.borrow().clock.now_us();
                let expected = if fault == 0 {
                    Error::Timeout(crate::audio::Phase::CodecHeadsetDetection)
                } else {
                    Error::RouteRejected
                };
                assert_eq!(controller.poll_conexant_headset(&graph), Err(expected));
                if fault == 0 {
                    assert_eq!(model.borrow().conexant_detection_reads, 3);
                    assert!(model.borrow().clock.now_us() - before >= 60_000);
                }
                let before = access_counts(&model);
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
                assert_eq!(controller.routes.len(), 1);
                assert_eq!(controller.conexant_codecs.len(), 1);
                {
                    let mut m = model.borrow_mut();
                    m.conexant_vendor_fault = None;
                    m.reject_route_control = None;
                    m.conexant_mic_fault_after = None;
                }
                controller.reinitialize().unwrap();
                assert!(controller.conexant_codecs.is_empty());
            }
        }

        #[test]
        fn conexant_headset_cold_failures_and_missing_actual_controls_refuse_without_false_readiness()
         {
            for fault in 0..6 {
                let mut fixture = Fixture::new();
                let model = headset_device(0x14f1_1f87, true);
                if fault == 0 {
                    model.borrow_mut().parameters.insert((0x19, 0x0c), 0x120);
                }
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                if fault == 1 {
                    model.borrow_mut().parameters.insert((0x1c, 9), u32::MAX);
                }
                if fault == 2 {
                    model.borrow_mut().pin_senses.insert(0x19, u32::MAX);
                }
                if fault == 3 {
                    model.borrow_mut().reject_route_control = Some(0xf07);
                }
                if fault == 4 {
                    model.borrow_mut().drop_reply_command = Some((0x1c << 20) | 0x3be10);
                }
                if fault == 5 {
                    model.borrow_mut().conexant_vendor_fault = Some(0x3be);
                }
                let before = model.borrow().commands.len();
                assert!(
                    controller
                        .initialize_conexant_headset_codec(&graph)
                        .is_err()
                );
                if fault < 2 {
                    assert!(controller.conexant_codecs.is_empty());
                    assert!(
                        model.borrow().commands[before..]
                            .iter()
                            .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
                    );
                } else {
                    assert_eq!(controller.conexant_codecs.len(), 1);
                    assert!(controller.routing_failed);
                    assert_eq!(
                        controller.poll_conexant_headset(&graph),
                        Err(Error::NeedsReset)
                    );
                }
            }
        }
        fn minimum_mute_device(
            codec: u32,
            converter: u8,
            channels: u8,
            hardware_mute: bool,
        ) -> Rc<RefCell<Model>> {
            let model = device(codec, 3);
            let mut m = model.borrow_mut();
            m.parameters.insert((1, 4), (2 << 16) | 16);
            for node in 11..=0x11 {
                m.parameters.insert((node, 9), 0xf << 20);
            }
            let caps = 0x0000_1f1f | if hardware_mute { 1 << 31 } else { 0 };
            for node in [0x10, 0x11] {
                m.parameters
                    .insert((node, 9), u32::from(channels == 2) | (1 << 2) | (1 << 3));
                m.parameters.insert((node, 0x12), caps);
                if !hardware_mute {
                    m.outputs_without_hardware_mute.push(node);
                }
            }
            m.parameters.insert((4, 0x0e), 1);
            m.connection_words.insert((4, 0), u32::from(converter));
            drop(m);
            model
        }

        #[test]
        fn conexant_cx20561_actual_minimum_gain_mute_preserves_mono_stereo_and_hardware_mute() {
            for converter in [0x10, 0x11] {
                for channels in [1, 2] {
                    for hardware_mute in [false, true] {
                        let mut fixture = Fixture::new();
                        let model =
                            minimum_mute_device(0x14f1_5051, converter, channels, hardware_mute);
                        let mut controller = create(&model, &mut fixture, config()).unwrap();
                        let graph = controller.enumerate_codec(0).unwrap();
                        controller.initialize_conexant_codec(&graph).unwrap();
                        let route = graph
                            .analog_route(Direction::Playback, 4, converter)
                            .unwrap();
                        let stream = controller
                            .allocate_stream(
                                Direction::Playback,
                                PcmFormat {
                                    channels,
                                    ..stereo()
                                },
                                128,
                                2,
                                &mut fixture.allocator,
                            )
                            .unwrap();
                        let before = model.borrow().commands.len();
                        controller
                            .configure_analog_route(&graph, &route, stream, 0, playback_options())
                            .unwrap();
                        {
                            let m = model.borrow();
                            let gains: Vec<_> = m.commands[before..]
                                .iter()
                                .filter(|cmd| {
                                    (**cmd >> 20) & 127 == u32::from(converter)
                                        && (**cmd >> 16) & 15 == 3
                                })
                                .map(|cmd| *cmd as u8)
                                .collect();
                            assert_eq!(
                                gains,
                                if hardware_mute {
                                    vec![0x9f, 0x1f]
                                } else {
                                    vec![0, 0x1f]
                                }
                            );
                            for channel in 0..channels {
                                assert_eq!(m.amplifiers[&(converter, true, 0, channel)], 0x1f);
                            }
                        }
                        controller.write_pcm(stream, 0, &[0x51; 256]).unwrap();
                        controller.start(stream).unwrap();
                        controller
                            .set_conexant_cx20561_converter_muted(&graph, converter, true)
                            .unwrap();
                        for channel in 0..channels {
                            assert_eq!(
                                model.borrow().amplifiers[&(converter, true, 0, channel)],
                                if hardware_mute { 0x9f } else { 0 }
                            );
                        }
                        assert!(controller.status(stream).unwrap().running);
                        controller
                            .set_conexant_cx20561_converter_muted(&graph, converter, false)
                            .unwrap();
                        for channel in 0..channels {
                            assert_eq!(
                                model.borrow().amplifiers[&(converter, true, 0, channel)],
                                0x1f
                            );
                        }
                        model.borrow_mut().dma_step_bytes = 128;
                        advance(&model, 8);
                        assert!(controller.status(stream).unwrap().period_completed);
                        controller.shutdown().unwrap();
                        assert!(model.borrow().playback.len() >= 256);
                        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x51));
                    }
                }
            }
        }

        #[test]
        fn conexant_minimum_mute_policy_does_not_leak_to_other_codecs_or_nonowned_dacs() {
            let mut fixture = Fixture::new();
            let model = minimum_mute_device(0x14f1_5047, 0x10, 2, false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
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
            controller
                .configure_analog_route(&graph, &route, stream, 0, playback_options())
                .unwrap();
            let m = model.borrow();
            let gains: Vec<_> = m.commands[before..]
                .iter()
                .filter(|cmd| (**cmd >> 20) & 127 == 0x10 && (**cmd >> 16) & 15 == 3)
                .map(|cmd| *cmd as u8)
                .collect();
            assert_eq!(gains, vec![0x1f]);
            drop(m);
            let before = access_counts(&model);
            assert_eq!(
                controller.set_conexant_cx20561_converter_muted(&graph, 0x10, true),
                Err(Error::UnsupportedTopology)
            );
            assert_eq!(access_counts(&model), before);

            let mut fixture = Fixture::new();
            let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
            let before = access_counts(&model);
            assert_eq!(
                controller.set_conexant_cx20561_converter_muted(&graph, 0x11, true),
                Err(Error::RouteInUse)
            );
            assert_eq!(access_counts(&model), before);
            assert_eq!(
                controller.set_conexant_cx20561_converter_muted(&graph, 2, true),
                Err(Error::UnsupportedTopology)
            );
        }

        #[test]
        fn conexant_minimum_mute_rejected_physical_gain_or_live_amp_authority_quarantines_routes() {
            for changed_caps in [false, true] {
                let mut fixture = Fixture::new();
                let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller.initialize_conexant_codec(&graph).unwrap();
                let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                controller
                    .configure_analog_route(&graph, &route, stream, 0, playback_options())
                    .unwrap();
                if changed_caps {
                    model
                        .borrow_mut()
                        .parameters
                        .insert((0x10, 0x12), 0x0000_1f0f);
                } else {
                    model.borrow_mut().reject_amplifier = true;
                }
                assert_eq!(
                    controller.set_conexant_cx20561_converter_muted(&graph, 0x10, true),
                    Err(if changed_caps {
                        Error::InvalidCodecGraph
                    } else {
                        Error::RouteRejected
                    })
                );
                let before = access_counts(&model);
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
                assert_eq!(controller.routes.len(), 1);
                assert_eq!(controller.conexant_codecs.len(), 1);
                model.borrow_mut().reject_amplifier = false;
                controller.reinitialize().unwrap();
                assert!(controller.routes.is_empty());
            }
        }
        #[test]
        fn conexant_minimum_mute_inherits_live_group_caps_and_refuses_an_unusable_zero_db_code() {
            for refusal in 0..3 {
                let mut fixture = Fixture::new();
                let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
                {
                    let mut m = model.borrow_mut();
                    m.parameters
                        .insert((0x10, 9), if refusal == 2 { 1 } else { 1 | (1 << 2) }); // FG amp inheritance.
                    m.parameters.insert(
                        (1, 0x12),
                        if refusal == 1 {
                            0x0000_1f00
                        } else {
                            0x0000_1f1f
                        },
                    );
                }
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller.initialize_conexant_codec(&graph).unwrap();
                let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                let before = access_counts(&model);
                let result = controller.configure_analog_route(
                    &graph,
                    &route,
                    stream,
                    0,
                    playback_options(),
                );
                if refusal != 0 {
                    assert_eq!(result, Err(Error::UnsupportedTopology));
                    assert_eq!(access_counts(&model), before);
                    assert!(!controller.routing_failed);
                } else {
                    result.unwrap();
                    let before = model.borrow().commands.len();
                    controller
                        .set_conexant_cx20561_converter_muted(&graph, 0x10, true)
                        .unwrap();
                    assert_eq!(model.borrow().amplifiers[&(0x10, true, 0, 0)], 0);
                    assert!(model.borrow().commands[before..].contains(&((1 << 20) | 0xf0012)));
                    model.borrow_mut().parameters.insert((1, 0x12), u32::MAX);
                    assert_eq!(
                        controller.set_conexant_cx20561_converter_muted(&graph, 0x10, false),
                        Err(Error::InvalidCodecGraph)
                    );
                    assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                }
            }
        }
    }
    mod sigmatel {
        use super::*;
        fn device(id: u32) -> Rc<RefCell<Model>> {
            let model = analog_model();
            let mut m = model.borrow_mut();
            m.parameters.insert((0, 0), id);
            m.parameters.insert((1, 4), (2 << 16) | 13);
            m.parameters.insert((1, 0x11), 8);
            m.route_controls.insert((1, 0xf15), 0xa5);
            m.route_controls.insert((1, 0xf16), 0x5a);
            m.route_controls.insert((1, 0xf17), 0x3c);
            for node in 8..=0x0e {
                m.parameters.insert((node, 9), 0xf << 20);
            }
            m.parameters.insert((8, 9), (4 << 20) | 1 | (1 << 8));
            m.parameters.insert((8, 0x0c), 0x18 | (1 << 16));
            m.parameters.insert((8, 0x0e), 1);
            m.connection_words.insert((8, 0), 7);
            // The fixed DAC0 mux can carry a real output route.
            m.parameters.insert((6, 9), (3 << 20) | 1 | (1 << 8));
            m.parameters.insert((6, 0x0e), 1);
            m.connection_words.insert((6, 0), 2);
            m.parameters.insert((7, 9), (3 << 20) | 1 | (1 << 8));
            m.parameters.insert((7, 0x0e), 1);
            m.connection_words.insert((7, 0), 2);
            m.parameters
                .insert((0x0e, 9), (2 << 20) | 1 | (1 << 2) | (1 << 8));
            m.parameters.insert((0x0e, 0x0e), 1);
            m.connection_words.insert((0x0e, 0), 6);
            m.connection_words
                .insert((4, 0), if id == 0x8384_7690 { 7 } else { 0x0e });
            m.parameters.insert((5, 0x0c), 0x20 | 0x3700 | 7);
            m.pin_defaults.insert(5, 0x03a1_0020);
            m.pin_senses.insert(5, 0x8000_005a);
            drop(m);
            model
        }
        #[test]
        fn sigmatel_actual_fixed_startup_gpio_preservation_and_native_duplex_pcm() {
            for id in [
                0x8384_7690,
                0x8384_7632,
                0x8384_7633,
                0x8384_7634,
                0x8384_7635,
                0x8384_7636,
                0x8384_7637,
            ] {
                let mut fixture = Fixture::new();
                let model = device(id);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let report = controller.initialize_sigmatel_codec(&graph).unwrap();
                assert_eq!(report.codec_id, id);
                assert_eq!(report.revision_id, 0x0010_0100);
                assert_eq!(report.subsystem_id, 0x1043_8693);
                assert_eq!(
                    report.gpio,
                    SigmatelGpio {
                        mask: 0x5a,
                        direction: 0x3c,
                        data: 0xa5
                    }
                );
                {
                    let m = model.borrow();
                    assert_eq!(m.route_controls[&(1, 0xfe7)], 0);
                    assert_eq!(m.route_controls[&(1, 0xf15)], 0xa5);
                    assert_eq!(m.route_controls[&(1, 0xf16)], 0x5a);
                    assert_eq!(m.route_controls[&(1, 0xf17)], 0x3c);
                    let dir = m
                        .command_times
                        .iter()
                        .find(|(cmd, _)| (*cmd >> 8) & 0xfff == 0x717)
                        .unwrap()
                        .1;
                    let data = m
                        .command_times
                        .iter()
                        .find(|(cmd, _)| (*cmd >> 8) & 0xfff == 0x715)
                        .unwrap()
                        .1;
                    assert!(data - dir >= 1000);
                    if id == 0x8384_7690 {
                        assert_eq!(report.profile, SigmatelProfile::Stac9200);
                        assert_eq!(report.eapd, Some((8, 2)));
                        assert_eq!(m.route_controls[&(7, 0xf01)], 0);
                        assert_eq!(m.route_controls[&(8, 0xf0c)], 2);
                    } else {
                        assert_eq!(report.profile, SigmatelProfile::Stac925x);
                        assert_eq!(report.master_amplifier, Some((0x0e, 0x80)));
                        for channel in 0..2 {
                            assert_eq!(m.amplifiers[&(0x0e, true, 0, channel)], 0x80);
                        }
                    }
                }
                let before = access_counts(&model);
                assert_eq!(
                    controller.initialize_sigmatel_codec(&graph),
                    Err(Error::RouteInUse)
                );
                assert_eq!(access_counts(&model), before);
                let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
                let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
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
                assert_eq!(
                    controller.configure_analog_route(
                        &graph,
                        &output,
                        playback,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: Some(true)
                        }
                    ),
                    Err(Error::InvalidPinControl)
                );
                controller
                    .configure_analog_route(
                        &graph,
                        &output,
                        playback,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: None,
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
                if id != 0x8384_7690 {
                    for channel in 0..2 {
                        assert_eq!(model.borrow().amplifiers[&(0x0e, true, 0, channel)], 0x1f);
                    }
                }
                let sense = controller.poll_pin_sense(&graph, 5).unwrap();
                assert!(sense.present);
                assert_eq!(sense.impedance_code, Some(0x5a));
                assert!(model.borrow().sense_triggers.is_empty());
                controller.write_pcm(playback, 0, &[0x92; 256]).unwrap();
                controller.fill_capture(capture, 0xa5).unwrap();
                controller.start(capture).unwrap();
                controller.start(playback).unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 8);
                assert!(controller.status(playback).unwrap().period_completed);
                assert!(controller.status(capture).unwrap().period_completed);
                controller.stop(capture).unwrap();
                let mut samples = [0; 256];
                controller.read_pcm(capture, 0, &mut samples).unwrap();
                assert_eq!(samples, core::array::from_fn(|index| index as u8));
                controller.shutdown().unwrap();
                let m = model.borrow();
                assert!(m.playback.len() >= 256);
                assert!(m.playback.iter().all(|byte| *byte == 0x92));
                for pin in [4, 5, 8] {
                    assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
                }
            }
        }
        #[test]
        fn sigmatel_startup_gpio_mux_eapd_amp_and_quiet_failures_retain_real_ownership() {
            for id in [0x8384_7690, 0x8384_7632] {
                for fault in 0..9 {
                    let mut fixture = Fixture::new();
                    let model = device(id);
                    let mut controller = create(&model, &mut fixture, config()).unwrap();
                    let graph = controller.enumerate_codec(0).unwrap();
                    if fault < 8 {
                        let mut m = model.borrow_mut();
                        m.reject_route_after_write = matches!(fault, 1..=3);
                        match fault {
                            0 => m.power_stuck = true,
                            1 => m.reject_route_control = Some(0xf16),
                            2 => m.reject_route_control = Some(0xf17),
                            3 => m.reject_route_control = Some(0xf15),
                            4 => m.reject_route_control = Some(0xf01),
                            5 => {
                                if id == 0x8384_7690 {
                                    m.reject_route_control = Some(0xf0c);
                                } else {
                                    m.reject_amplifier = true;
                                }
                            }
                            6 => m.reject_route_control = Some(0xf15),
                            _ => m.drop_reply_command = Some((1 << 20) | (0x7e7 << 8)),
                        }
                    }
                    let result = controller.initialize_sigmatel_codec(&graph);
                    if fault < 8 {
                        assert!(result.is_err());
                    } else {
                        result.unwrap();
                        model.borrow_mut().reject_route_control = Some(0xf07);
                        assert_eq!(controller.shutdown(), Err(Error::RouteRejected));
                        assert!(controller.stopped);
                    }
                    assert_eq!(controller.sigmatel_codecs.len(), 1);
                    let before = access_counts(&model);
                    assert_eq!(
                        controller.initialize_sigmatel_codec(&graph),
                        Err(Error::NeedsReset)
                    );
                    assert_eq!(access_counts(&model), before);
                    {
                        let mut m = model.borrow_mut();
                        m.power_stuck = false;
                        m.reject_route_control = None;
                        m.reject_route_after_write = false;
                        m.drop_reply_command = None;
                        m.reject_amplifier = false;
                    }
                    controller.reinitialize().unwrap();
                    assert!(controller.sigmatel_codecs.is_empty());
                    assert_eq!(
                        controller.initialize_sigmatel_codec(&graph),
                        Err(Error::InvalidCodecGraph)
                    );
                }
            }
        }
        #[test]
        fn sigmatel_refuses_unknown_fixed_metadata_and_gpio_authority_before_effects() {
            for fault in 0..6 {
                let mut fixture = Fixture::new();
                let model = device(if fault == 0 {
                    0x111d_76b0
                } else if fault == 5 {
                    0x8384_7632
                } else {
                    0x8384_7690
                });
                if fault == 1 {
                    model.borrow_mut().parameters.insert((8, 0x0c), 0x18);
                }
                if fault == 2 {
                    model.borrow_mut().parameters.insert((1, 0x11), 9);
                }
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                if fault == 3 {
                    model.borrow_mut().parameters.insert((0, 2), u32::MAX);
                }
                if fault == 4 {
                    model.borrow_mut().parameters.insert((7, 9), 0xf << 20);
                }
                if fault == 5 {
                    model.borrow_mut().parameters.insert((1, 0x12), 0x0000_1f1f);
                }
                let before = model.borrow().commands.len();
                assert!(controller.initialize_sigmatel_codec(&graph).is_err());
                assert!(controller.sigmatel_codecs.is_empty());
                assert!(
                    model.borrow().commands[before..]
                        .iter()
                        .all(|cmd| (*cmd >> 8) & 0xfff >= 0xf00)
                );
            }
        }
        #[test]
        fn sigmatel_owned_live_identity_loss_and_stream_quiescence_failures_block_reuse() {
            for quiet_failure in [false, true] {
                let mut fixture = Fixture::new();
                let model = device(0x8384_7690);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller.initialize_sigmatel_codec(&graph).unwrap();
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
                controller
                    .configure_analog_route(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: None,
                        },
                    )
                    .unwrap();
                if quiet_failure {
                    controller.start(stream).unwrap();
                    model.borrow_mut().stream_stop_stuck = true;
                    let before = model.borrow().commands.len();
                    assert!(controller.shutdown().is_err());
                    assert_eq!(model.borrow().commands.len(), before);
                    assert!(!controller.stopped);
                    model.borrow_mut().stream_stop_stuck = false;
                } else {
                    model.borrow_mut().parameters.insert((8, 0x0c), 0x18);
                    assert_eq!(
                        controller.poll_pin_sense(&graph, 5),
                        Err(Error::InvalidCodecGraph)
                    );
                    let before = access_counts(&model);
                    assert_eq!(controller.start(stream), Err(Error::NeedsReset));
                    assert_eq!(access_counts(&model), before);
                    let before = model.borrow().commands.len();
                    assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
                    assert!(controller.stopped);
                    assert_eq!(model.borrow().commands.len(), before);
                }
                assert_eq!(controller.routes.len(), 1);
                assert_eq!(controller.sigmatel_codecs.len(), 1);
                controller.reinitialize().unwrap();
                assert!(controller.routes.is_empty());
                assert!(controller.sigmatel_codecs.is_empty());
            }
        }
        #[test]
        fn sigmatel_zero_gpio_and_observed_undeclared_gpio_levels_are_not_inferred_away() {
            for active_undeclared in [false, true] {
                let mut fixture = Fixture::new();
                let model = device(0x8384_7690);
                {
                    let mut m = model.borrow_mut();
                    m.parameters.insert((1, 0x11), 0);
                    for verb in [0xf15, 0xf16, 0xf17] {
                        m.route_controls.insert((1, verb), 0);
                    }
                    if active_undeclared {
                        m.route_controls.insert((1, 0xf15), 1);
                    }
                }
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let before = model.borrow().commands.len();
                let result = controller.initialize_sigmatel_codec(&graph);
                if active_undeclared {
                    assert_eq!(result, Err(Error::RouteRejected));
                    assert_eq!(controller.sigmatel_codecs.len(), 1);
                    assert!(controller.routing_failed);
                    assert!(
                        !model.borrow().commands[before..]
                            .iter()
                            .any(|cmd| (*cmd >> 8) & 0xfff == 0x7e7)
                    );
                } else {
                    assert_eq!(
                        result.unwrap().gpio,
                        SigmatelGpio {
                            mask: 0,
                            direction: 0,
                            data: 0
                        }
                    );
                    assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0);
                    controller.shutdown().unwrap();
                }
            }
        }
        #[test]
        fn sigmatel_and_conexant_backends_cannot_replace_each_others_owned_address() {
            for initial_sigmatel in [false, true] {
                let mut fixture = Fixture::new();
                let model = device(if initial_sigmatel {
                    0x8384_7690
                } else {
                    0x14f1_5047
                });
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                if initial_sigmatel {
                    controller.initialize_sigmatel_codec(&graph).unwrap();
                } else {
                    controller.initialize_conexant_codec(&graph).unwrap();
                }
                model.borrow_mut().parameters.insert(
                    (0, 0),
                    if initial_sigmatel {
                        0x14f1_5047
                    } else {
                        0x8384_7690
                    },
                );
                let new_graph = controller.enumerate_codec(0).unwrap();
                let before = access_counts(&model);
                if initial_sigmatel {
                    assert_eq!(
                        controller.initialize_conexant_codec(&new_graph),
                        Err(Error::RouteInUse)
                    );
                    assert!(controller.conexant_codecs.is_empty());
                } else {
                    assert_eq!(
                        controller.initialize_sigmatel_codec(&new_graph),
                        Err(Error::RouteInUse)
                    );
                    assert!(controller.sigmatel_codecs.is_empty());
                }
                assert_eq!(access_counts(&model), before);
                assert_eq!(
                    controller.conexant_codecs.len() + controller.sigmatel_codecs.len(),
                    1
                );
            }
        }
    }
}
