// SPDX-License-Identifier: GPL-2.0-only
//! Polled standard HD Audio transport and PCM DMA, adapted from Linux
//! `sound/hda/core/{controller,stream,device}.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//!
//! This is the conventional HDA MMIO core. The `pci` module prepares a bounded
//! conventional Intel/ATI/AMD subset. Intel DSP/firmware ownership, other vendor quirks, ACPI
//! power resources, the HDMI GPU port provider, OEM amplifier/pin policy, suspend and
//! guest audio bridging remain platform responsibilities. An ID match alone
//! does not establish exclusive controller ownership.
//! Hardware shutdown is distinct from resource retirement. The outer owner
//! must independently retire payload/root/IRQ/work/CPU users before unmapping
//! DMA or releasing controller resources. Error or Drop proves no completion.
use crate::Timer;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use super::{Error, Phase};
use crate::bus::dma::{DmaAllocator, DmaBuffer};

mod cache;
mod construction;
pub use construction::{Construction, ConstructionFailure};
mod cirrus;
mod codec;
pub mod cold;
pub mod digital;
pub use cirrus::{
    CirrusCoefficient, CirrusInputAmplifier, CirrusOutputAmplifier, CirrusProfile, CirrusReport,
    CirrusSpeakerBoost,
};
mod conexant;
pub use conexant::{
    ConexantEapdMode, ConexantHeadsetInitialization, ConexantHeadsetKind, ConexantHeadsetReport,
    ConexantReport,
};
mod extended;
pub use extended::LinkClock;
pub mod hdmi;
mod lifecycle;
mod unsolicited;
pub use unsolicited::{JackNotificationId, UnsolicitedEvent, UnsolicitedResponse};
pub mod pci;
mod pins;
mod registers;
pub use pins::{AnalogEndpoint, PinConfiguration, PinConnection, PinDevice, PinSense};
mod realtek;
pub use realtek::{
    Alc269CommonReport, Alc269Variant, AmplifierLevel, CoefficientChange, RealtekCaptureGain,
    RealtekCommonReport, RealtekDualHeadphoneReport, RealtekFamily, RealtekHeadphoneReport,
    RealtekHeadphoneRoute, RealtekOem, RealtekReport,
};
mod routing;
mod setup;
pub use setup::CodecSetup;
mod sigmatel;
pub use sigmatel::{
    Idt73PowerReport, Idt83PortPower, Idt83PowerReport, Idt95PowerReport, SigmatelGpio,
    SigmatelProfile, SigmatelReport,
};
mod stream;
pub use codec::{CodecGraph, FunctionGroup, PcmCapabilities, Verb, Widget, WidgetKind};
pub use lifecycle::{CodecDiscovery, CodecFailure, DiscoveryFailure, ProbePolicy};
use registers::*;
pub use registers::{MmioRegisters, Registers};
pub use routing::{AnalogRoute, PinOptions, Vref};
use stream::{ConverterBinding, Stream};
pub use stream::{PositionInfo, PositionPolicy, StreamId, StreamStatus, StreamTagPolicy};

/// Select from a controller identity/quirk table in platform glue.
/// Intel/AMD standard reset uses the set-then-clear handshake; a self-clearing
/// controller must be explicitly identified, never inferred from a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorbReset {
    Handshake,
    SelfClearing,
}

/// Mandatory reset preparation selected from a controller identity.
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
            // snd_hdac_bus_get_response_rirb waits a second.
            verb_timeout_us: 1_000_000,
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

// Identities are never returned, including after failed construction or shutdown.
// Exhaustion permanently refuses new controllers instead of recycling a token.
static NEXT_CONTROLLER_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControllerIdentity(u64);

impl ControllerIdentity {
    fn reserve(identities: &AtomicU64) -> Result<Self, Error> {
        identities
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1).filter(|_| next != 0)
            })
            .map(Self)
            .map_err(|_| Error::ControllerIdentitiesExhausted)
    }
}

/// Non-recycled controller identity plus a non-recycled reset generation.
/// Handles can outlive both the controller and its reused DMA allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControllerToken {
    owner: ControllerIdentity,
    generation: u64,
}

pub struct Controller<R, T> {
    registers: core::mem::ManuallyDrop<R>,
    timer: core::mem::ManuallyDrop<T>,
    minimum_error: core::cell::Cell<Option<Error>>,
    effect_error: core::cell::Cell<Option<Error>>,
    reset_cleanup_error: Option<Error>,
    reset_error: Option<Error>,
    config: Config,
    capabilities: Capabilities,
    codec_mask: u16,
    corb: core::mem::ManuallyDrop<DmaBuffer>,
    rirb: core::mem::ManuallyDrop<DmaBuffer>,
    corb_entries: u16,
    rirb_entries: u16,
    corb_wp: u16,
    rirb_rp: u16,
    command_poisoned: bool,
    /// `rirb.cmds` and `rirb.res`: commands each codec has yet to answer, and
    /// its latest answer.
    outstanding: [u8; 15],
    answers: [u32; 15],
    /// azx `single_cmd` and `probing`; hda_bus `allow_bus_reset`,
    /// `response_reset` and `in_reset`.
    single_command: bool,
    probing: bool,
    allow_bus_reset: bool,
    response_reset: bool,
    in_reset: bool,
    writes: cache::Writes,
    stopped: bool,
    streams: Vec<Option<Stream>>,
    routes: Vec<(StreamId, AnalogRoute)>,
    // Non-route codec controls: owner, codec address, node. Observing or
    // preconditioning a pin does not invent a converter path for it.
    codec_controls: Vec<(StreamId, u8, u8)>,
    converter_bindings: Vec<ConverterBinding>,
    realtek_codecs: Vec<realtek::State>,
    conexant_codecs: Vec<conexant::State>,
    sigmatel_codecs: Vec<sigmatel::State>,
    cirrus_codecs: Vec<cirrus::State>,
    hdmi_ports: Vec<Option<hdmi::Port>>,
    routing_failed: bool,
    token: ControllerToken,
    lifecycle_failed: bool,
    discovery_ready: bool,
    extended: Option<extended::ExtendedCapabilities>,
    unsolicited: unsolicited::State,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// A vendor codec profile's common precondition: `graph` belongs to this
    /// controller, no failure needs a reset and the controller is running.
    fn vendor_codec_guard(&self, graph: &CodecGraph) -> Result<(), Error> {
        self.minimum_guard()?;
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        if self.routing_failed || self.lifecycle_failed || self.command_poisoned {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        Ok(())
    }
    /// Claim and reset a controller, then start its CORB/RIRB DMA engines.
    ///
    /// # Safety
    /// The caller exclusively owns a powered, conventional HDA controller and
    /// all of its fixed/bidirectional stream descriptors. Registers must expose
    /// at least 0x440 bytes of uncached BAR0 using native access widths; no
    /// firmware, DSP, AML, SMM or other CPU may concurrently use the hardware.
    /// The allocator must return unique coherent CPU-accessible memory with
    /// contiguous controller IOVAs through this exact requester/root. CPU VA,
    /// PA and IOVA may differ; none may replace another. Keep all DMA
    /// memory and MMIO alive for the boot. Constructor refusal keeps the same
    /// register/timer and partial DMA or entire core in its owning carrier.
    /// Drop performs no reset, unmap or release; stop acknowledgement may have
    /// failed. Keep the independent allocator/root graph alongside that carrier.
    /// Apply platform PCI/snoop/power/clock/quirk setup before calling this.
    /// `config.dma_address_bits` must reflect the identity/platform DMA
    /// reachability ceiling; GCAP's 64-bit flag alone does not establish it.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the same physical owner graph without allocating on failure"
    )]
    pub unsafe fn new(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
    ) -> Result<Self, ConstructionFailure<R, T>> {
        // SAFETY: forwards the complete controller/allocator ownership contract.
        unsafe {
            Self::new_with_identities(
                registers,
                timer,
                allocator,
                config,
                &NEXT_CONTROLLER_IDENTITY,
            )
        }
    }

    // The production namespace is permanent. A private injectable namespace lets
    // tests prove exhaustion without resetting or consuming the global counter.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the same physical owner graph without allocating on failure"
    )]
    unsafe fn new_with_identities(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
        identities: &AtomicU64,
    ) -> Result<Self, ConstructionFailure<R, T>> {
        // SAFETY: forwarded legacy constructor ownership prerequisites.
        unsafe { Self::construct(registers, timer, allocator, config, identities, None) }
    }

    /// Start new rings only after inherited engines have been acknowledged
    /// stopped and their original-root/IRQ/work owners independently retired.
    ///
    /// # Safety
    /// The stopped observation belongs to these exact registers/configuration
    /// epoch. No producer/reset/firmware user could resume after it. The
    /// original root drained before the paired private domain and allocator
    /// were installed. All normal new ownership/coherence prerequisites hold.
    /// An outer owner retains the actual register/allocator graph across every
    /// constructor error or unwind; this operation never retries failed reset.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the same physical owner graph without allocating on failure"
    )]
    pub unsafe fn new_after_stop(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
        stopped: cold::Stopped,
    ) -> Result<Self, ConstructionFailure<R, T>> {
        // SAFETY: forwarded same-owner stopped/root/allocator prerequisites.
        unsafe {
            Self::construct(
                registers,
                timer,
                allocator,
                config,
                &NEXT_CONTROLLER_IDENTITY,
                Some(stopped),
            )
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the same physical owner graph without allocating on failure"
    )]
    unsafe fn construct(
        registers: R,
        timer: T,
        allocator: &mut dyn DmaAllocator,
        config: Config,
        identities: &AtomicU64,
        stopped: Option<cold::Stopped>,
    ) -> Result<Self, ConstructionFailure<R, T>> {
        let mut custody = Construction::new(registers, timer);
        let result = (|| -> Result<(), Error> {
            if config.transition_timeout_us == 0
                || config.verb_timeout_us == 0
                || !(32..=64).contains(&config.dma_address_bits)
            {
                return Err(Error::InvalidConfiguration);
            }
            config.probe_policy.budget()?;
            // Reserve before any register-provider callback, timer or DMA effect.
            let identity = ControllerIdentity::reserve(identities)?;
            custody
                .timer
                .as_ref()
                .unwrap()
                .check()
                .map_err(Error::MinimumDelay)?;
            let registers = custody.registers.as_mut().unwrap();
            registers.validate_config(&config)?;
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
            if let Some(stopped) = &stopped
                && stopped.streams() != total
            {
                return Err(Error::UnsupportedTopology);
            }
            let extended = if config.reset_policy == ResetPolicy::IntelClockGate {
                Some(extended::inspect(registers, total)?)
            } else {
                None
            };
            // Allocations remain alive if hardware refuses to stop on an error.
            custody.corb = Some(match allocator.allocate(1024, 128) {
                Ok(buffer) => buffer,
                Err(error) => {
                    custody.allocation_error = Some(error);
                    return Err(Error::NoDmaMemory);
                }
            });
            custody.rirb = Some(match allocator.allocate(2048, 128) {
                Ok(buffer) => buffer,
                Err(error) => {
                    custody.allocation_error = Some(error);
                    return Err(Error::NoDmaMemory);
                }
            });
            let corb = custody.corb.as_ref().unwrap();
            let rirb = custody.rirb.as_ref().unwrap();
            Self::check_dma(corb, 128, capabilities.dma_address_bits)?;
            Self::check_dma(rirb, 128, capabilities.dma_address_bits)?;
            if corb.len() < 1024 || rirb.len() < 2048 {
                return Err(Error::InvalidBuffer);
            }
            let controller = Self {
                registers: core::mem::ManuallyDrop::new(custody.registers.take().unwrap()),
                timer: core::mem::ManuallyDrop::new(custody.timer.take().unwrap()),
                minimum_error: core::cell::Cell::new(None),
                effect_error: core::cell::Cell::new(None),
                reset_cleanup_error: None,
                reset_error: None,
                config,
                capabilities,
                codec_mask: 0,
                token: ControllerToken {
                    owner: identity,
                    generation: 1,
                },
                lifecycle_failed: false,
                discovery_ready: false,
                extended,
                unsolicited: unsolicited::State::new(),
                corb: core::mem::ManuallyDrop::new(custody.corb.take().unwrap()),
                rirb: core::mem::ManuallyDrop::new(custody.rirb.take().unwrap()),
                corb_entries: 0,
                rirb_entries: 0,
                corb_wp: 0,
                rirb_rp: 0,
                command_poisoned: false,
                outstanding: [0; 15],
                answers: [0; 15],
                single_command: false,
                probing: false,
                allow_bus_reset: false,
                response_reset: false,
                in_reset: false,
                writes: cache::Writes::default(),
                stopped: false,
                streams: (0..total).map(|_| None).collect(),
                routes: Vec::new(),
                codec_controls: Vec::new(),
                converter_bindings: Vec::new(),
                realtek_codecs: Vec::new(),
                conexant_codecs: Vec::new(),
                sigmatel_codecs: Vec::new(),
                cirrus_codecs: Vec::new(),
                hdmi_ports: Vec::new(),
                routing_failed: false,
            };
            custody.controller = Some(alloc::boxed::Box::new(controller));
            let controller = custody.controller.as_mut().unwrap();
            let initialized = if stopped.is_some() {
                controller.initialize_after_stop()
            } else {
                controller.initialize()
            };
            if let Err(error) = initialized {
                // The returned primary belongs to this same retained graph even
                // if explicit shutdown below fails or unwinds. A lost access or
                // minimum authority never licenses another hardware effect.
                if controller.reset_error.is_none() {
                    controller.reset_error = Some(error);
                }
                controller.lifecycle_failed = true;
                if controller.first_effect_error().is_none()
                    && controller.reset_cleanup_error.is_none()
                {
                    controller.reset_cleanup_error = controller.shutdown().err();
                }
                return Err(error);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(*custody.controller.take().unwrap()),
            Err(error) => Err(crate::Refusal {
                error,
                owner: custody,
            }),
        }
    }

    /// Consume stopped core buffers after independent platform drains, keeping
    /// its original registers and timer available for outer resource retirement.
    ///
    /// # Safety
    /// Payload writes, IRQ/service/work and all CPU buffer users are retired
    /// through the exact current root/owner. No reset/restart can occur. The
    /// allocator/root remain alive while this drops every core DMA reference.
    pub unsafe fn into_shutdown_resources(mut self) -> Result<(R, T), alloc::boxed::Box<Self>> {
        if !self.stopped || self.lifecycle_failed || self.first_effect_error().is_some() {
            return Err(alloc::boxed::Box::new(self));
        }
        // SAFETY: the caller has completed every payload/IRQ/work/CPU user;
        // this is the sole explicit consumption of the original core graph.
        unsafe {
            core::mem::ManuallyDrop::drop(&mut self.corb);
            core::mem::ManuallyDrop::drop(&mut self.rirb);
        }
        drop(core::mem::take(&mut self.streams));
        drop(core::mem::take(&mut self.routes));
        drop(core::mem::take(&mut self.codec_controls));
        drop(core::mem::take(&mut self.converter_bindings));
        drop(core::mem::take(&mut self.realtek_codecs));
        drop(core::mem::take(&mut self.conexant_codecs));
        drop(core::mem::take(&mut self.sigmatel_codecs));
        drop(core::mem::take(&mut self.cirrus_codecs));
        drop(core::mem::take(&mut self.hdmi_ports));
        // SAFETY: these original owners are moved once after independent drains.
        Ok(unsafe {
            (
                core::mem::ManuallyDrop::take(&mut self.registers),
                core::mem::ManuallyDrop::take(&mut self.timer),
            )
        })
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    pub fn codec_mask(&self) -> u16 {
        self.codec_mask
    }

    pub(super) fn check_dma(buffer: &DmaBuffer, align: u64, address_bits: u8) -> Result<(), Error> {
        check_dma_range(buffer.bus_address(), buffer.len(), align, address_bits)
    }

    pub(super) fn wait(
        &mut self,
        phase: Phase,
        mut predicate: impl FnMut(&mut R) -> bool,
    ) -> Result<(), Error> {
        self.minimum_guard()?;
        let start = self.timer.now_us();
        loop {
            if predicate(&mut *self.registers) {
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

    /// Primary returned error of the latest reset bracket, kept before cleanup.
    pub fn reset_error(&self) -> Option<Error> {
        self.reset_error
    }
    pub fn reset_cleanup_error(&self) -> Option<Error> {
        self.reset_cleanup_error
    }
    pub fn first_minimum_error(&self) -> Option<Error> {
        self.minimum_error.get()
    }
    pub fn first_effect_error(&self) -> Option<Error> {
        self.effect_error.get().or(self.minimum_error.get())
    }
    fn fence_effect_error(&self, error: Error) {
        if matches!(
            error,
            Error::Config(_)
                | Error::PciCapability(_)
                | Error::MinimumDelay(_)
                | Error::Interrupted
        ) {
            if self.effect_error.get().is_none() {
                self.effect_error.set(Some(error));
            }
            if matches!(error, Error::MinimumDelay(_) | Error::Interrupted)
                && self.minimum_error.get().is_none()
            {
                self.minimum_error.set(Some(error));
            }
        }
    }
    fn reset_clock_gate_effect(&mut self, enabled: bool) -> Result<(), Error> {
        if let Some(error) = self.first_effect_error() {
            return Err(error);
        }
        // Close effect admission BEFORE the external hook. Caught unwind
        // retains Interrupted without claiming that it was a minimum failure.
        self.effect_error.set(Some(Error::Interrupted));
        let result = self.registers.reset_clock_gate(enabled);
        self.effect_error.set(None);
        if let Err(error) = result {
            self.fence_effect_error(error);
        }
        result
    }
    fn minimum_guard(&self) -> Result<(), Error> {
        if let Some(error) = self.first_effect_error() {
            return Err(error);
        }
        self.minimum_error.set(Some(Error::Interrupted));
        match self.timer.check() {
            Ok(()) => {
                self.minimum_error.set(None);
                Ok(())
            }
            Err(cause) => {
                let error = Error::MinimumDelay(cause);
                self.minimum_error.set(Some(error));
                Err(error)
            }
        }
    }
    fn minimum_wait(
        timer: &T,
        failure: &core::cell::Cell<Option<Error>>,
        us: u64,
    ) -> Result<(), Error> {
        if let Some(error) = failure.get() {
            return Err(error);
        }
        failure.set(Some(Error::Interrupted));
        match timer.check().and_then(|()| timer.wait_us(us)) {
            Ok(()) => {
                failure.set(None);
                Ok(())
            }
            Err(cause) => {
                let error = Error::MinimumDelay(cause);
                failure.set(Some(error));
                Err(error)
            }
        }
    }
    fn delay(&mut self, us: u64) -> Result<(), Error> {
        self.minimum_guard()?;
        let previous = (
            self.lifecycle_failed,
            self.command_poisoned,
            self.routing_failed,
        );
        self.lifecycle_failed = true;
        self.command_poisoned = true;
        self.routing_failed = true;
        Self::minimum_wait(&*self.timer, &self.minimum_error, us)?;
        (
            self.lifecycle_failed,
            self.command_poisoned,
            self.routing_failed,
        ) = previous;
        Ok(())
    }

    fn stop_commands(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        self.registers.write8(CORBCTL, 0);
        self.registers.write8(RIRBCTL, 0);
        self.wait(Phase::CommandStop, |r| {
            r.read8(CORBCTL) & COMMAND_RUN == 0 && r.read8(RIRBCTL) & COMMAND_RUN == 0
        })
    }

    fn initialize(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        self.refresh_extended()?;
        self.registers.write32(INTCTL, 0);
        self.registers.write16(WAKEEN, 0);
        for index in 0..self.streams.len() as u8 {
            self.stop_descriptor(index)?;
        }
        self.stop_commands()?;
        self.registers.write32(DPLBASE, 0);
        self.registers.write32(DPUBASE, 0);
        self.initialize_after_stop()
    }

    fn initialize_after_stop(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        self.refresh_extended()?;
        if self.config.reset_policy == ResetPolicy::Generic {
            return self.initialize_link();
        }
        self.reset_cleanup_error = None;
        self.reset_error = None;
        if let Err(error) = self.reset_clock_gate_effect(false) {
            self.reset_error = Some(error);
            if self.first_effect_error().is_none() {
                self.reset_cleanup_error = self.reset_clock_gate_effect(true).err();
            }
            return Err(error);
        }
        let reset = self.initialize_link();
        if let Err(error) = reset {
            self.reset_error = Some(error);
            self.fence_effect_error(error);
        }
        if self.first_effect_error().is_some() {
            return reset;
        }
        let cleanup = self.reset_clock_gate_effect(true);
        match reset {
            Err(error) => {
                // Preserve the primary reset error beside any distinct hook
                // cleanup error; a cleanup denial has already fenced IO.
                self.reset_cleanup_error = cleanup.err();
                return Err(error);
            }
            Ok(()) => {
                if let Err(error) = cleanup {
                    self.reset_error = Some(error);
                    return Err(error);
                }
            }
        }
        self.refresh_extended()?;
        self.configure_extended_link()
    }

    fn initialize_link(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
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
        self.delay(500)?; // Linux: >=100us link/codec PLL reset assertion.
        self.registers.write32(GCTL, gctl | GCTL_RESET);
        self.wait(Phase::LinkResetExit, |r| {
            let value = r.read32(GCTL);
            value != u32::MAX && value & GCTL_RESET != 0
        })?;
        self.delay(1000)?; // Codec initialization requires >=540us after CRST.
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
            .write32(CORBLBASE, self.corb.bus_address() as u32);
        self.registers
            .write32(CORBUBASE, (self.corb.bus_address() >> 32) as u32);
        self.registers
            .write32(RIRBLBASE, self.rirb.bus_address() as u32);
        self.registers
            .write32(RIRBUBASE, (self.rirb.bus_address() >> 32) as u32);
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
        self.minimum_guard()?;
        if self.registers.read8(CORBSTS) & CORB_MEMORY != 0 {
            return Err(Error::CorbMemory);
        }
        Ok(())
    }

    /// `codec_exec_verb` over `azx_send_cmd`/`azx_get_response`. Responses
    /// carry no transaction ID, so, as in `snd_hdac_bus_update_rirb`, each
    /// codec counts its outstanding commands and a verb completes once its
    /// codec has answered every one; a late answer to a timed-out command is
    /// consumed by the next. A timeout outside probing either resets the bus
    /// once, where a codec allowed that (`allow_bus_reset`), and retries, or
    /// falls back to the immediate command interface for good.
    pub fn verb(&mut self, verb: Verb) -> Result<u32, Error> {
        self.minimum_guard()?;
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
        self.writes.remember(verb);
        self.exchange(verb)
    }

    fn exchange(&mut self, verb: Verb) -> Result<u32, Error> {
        self.minimum_guard()?;
        loop {
            let result = if self.single_command {
                self.single_verb(verb)
            } else {
                self.rirb_verb(verb)
            };
            match result {
                Ok(response) => {
                    // The communication recovered.
                    self.response_reset = false;
                    return Ok(response);
                }
                // azx_rirb_get_response: polling already; no MSI to disable.
                Err(Error::Timeout(Phase::Verb)) if !self.single_command && !self.probing => {
                    if self.allow_bus_reset && !self.response_reset && !self.in_reset {
                        self.response_reset = true;
                        self.bus_reset()?;
                        continue;
                    }
                    self.single_command = true;
                    self.response_reset = false;
                    // snd_hdac_bus_stop_cmd_io; rings that keep running stay
                    // owned by the device.
                    if let Err(error) = self.stop_commands() {
                        self.command_poisoned = true;
                        return Err(error);
                    }
                    return Err(Error::Timeout(Phase::Verb));
                }
                Err(error @ Error::Timeout(Phase::Verb)) => return Err(error),
                Err(error) => {
                    self.command_poisoned = true;
                    let _ = self.stop_commands();
                    return Err(error);
                }
            }
        }
    }

    /// `snd_hdac_bus_update_rirb`: unsolicited responses queue; a solicited
    /// one from a codec with nothing outstanding is spurious and dropped.
    fn update_rirb(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        self.command_fault()?;
        let wp = self.registers.read16(RIRBWP);
        if wp == u16::MAX {
            // The controller likely went to D3; nothing arrived.
            return Ok(());
        }
        if wp >= self.rirb_entries {
            return Err(Error::InvalidRingPointer);
        }
        fence(Ordering::Acquire);
        while self.rirb_rp != wp {
            self.rirb_rp = (self.rirb_rp + 1) % self.rirb_entries;
            let offset = usize::from(self.rirb_rp) * 8;
            let extra = u32::from_le(self.rirb.read::<u32>(offset + 4));
            let value = u32::from_le(self.rirb.read::<u32>(offset));
            let codec = usize::from((extra & 15) as u8);
            if extra & RESPONSE_UNSOL != 0 {
                self.unsolicited.receive(self.token, value, extra);
            } else if codec < 15 && self.outstanding[codec] != 0 {
                self.answers[codec] = value;
                self.outstanding[codec] -= 1;
            }
        }
        // azx_interrupt acknowledges both the response and overrun status;
        // responses an overrun lost time their commands out.
        self.registers.write8(RIRBSTS, RIRB_RESPONSE | RIRB_OVERRUN);
        Ok(())
    }

    /// `snd_hdac_bus_send_cmd` then `snd_hdac_bus_get_response_rirb`. Answers
    /// already queued are consumed first, as `azx_interrupt` would have.
    fn rirb_verb(&mut self, verb: Verb) -> Result<u32, Error> {
        self.minimum_guard()?;
        self.update_rirb()?;
        let rp = self.registers.read16(CORBRP);
        if rp >= self.corb_entries {
            return Err(Error::InvalidRingPointer);
        }
        let next = (self.corb_wp + 1) % self.corb_entries;
        if next == rp {
            return Err(Error::InvalidRingPointer);
        }
        let codec = usize::from(verb.codec());
        self.outstanding[codec] = self.outstanding[codec].saturating_add(1);
        self.corb.write(usize::from(next) * 4, verb.raw().to_le());
        fence(Ordering::SeqCst);
        self.corb_wp = next;
        self.registers.write16(CORBWP, next);
        let start = self.timer.now_us();
        loop {
            self.update_rirb()?;
            if self.outstanding[codec] == 0 {
                return Ok(self.answers[codec]);
            }
            if self.timer.now_us().wrapping_sub(start) >= u64::from(self.config.verb_timeout_us) {
                return Err(Error::Timeout(Phase::Verb));
            }
            self.timer.relax();
        }
    }

    /// `azx_single_send_cmd` and `azx_single_wait_for_response`: 50us for the
    /// interface to go idle, then 50us for the response.
    fn single_verb(&mut self, verb: Verb) -> Result<u32, Error> {
        self.minimum_guard()?;
        let start = self.timer.now_us();
        while self.registers.read16(IRS) & IRS_BUSY != 0 {
            if self.timer.now_us().wrapping_sub(start) >= SINGLE_COMMAND_US {
                return Err(Error::Timeout(Phase::Verb));
            }
            self.timer.relax();
        }
        let status = self.registers.read16(IRS);
        self.registers.write16(IRS, status | IRS_VALID);
        self.registers.write32(IC, verb.raw());
        let status = self.registers.read16(IRS);
        self.registers.write16(IRS, status | IRS_BUSY);
        let start = self.timer.now_us();
        loop {
            if self.registers.read16(IRS) & IRS_VALID != 0 {
                return Ok(self.registers.read32(IR));
            }
            if self.timer.now_us().wrapping_sub(start) >= SINGLE_COMMAND_US {
                return Err(Error::Timeout(Phase::Verb));
            }
            self.timer.relax();
        }
    }

    /// `snd_hda_bus_reset`: stop and fully reinitialize the controller, then
    /// resume each codec from its writes, as codec resume replays its
    /// register cache. Streams lose their descriptors to the link reset and
    /// stay stopped until released.
    fn bus_reset(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        if !self.writes.complete() {
            // Writes the cache could not key cannot be restored.
            return Err(Error::Timeout(Phase::Verb));
        }
        self.in_reset = true;
        let result = self.reset_chip().and_then(|()| {
            if self.unsolicited.capturing() {
                self.jack_gate(true)?;
            }
            // Codec resume does not fail the reset; a write that times out
            // here falls back to single commands for the rest.
            for verb in self.writes.replay() {
                let _ = self.exchange(verb);
            }
            Ok(())
        });
        self.in_reset = false;
        result
    }

    /// `azx_stop_chip` then `azx_init_chip(chip, true)`: a link and command
    /// ring reset that keeps the codec mask, unlike a new probe.
    pub(super) fn reset_chip(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        for stream in self.streams.iter_mut().flatten() {
            stream.running = false;
            stream.poisoned = true;
        }
        let mask = self.codec_mask;
        self.corb_wp = 0;
        self.rirb_rp = 0;
        self.outstanding = [0; 15];
        if let Err(error) = self.initialize() {
            self.command_poisoned = true;
            return Err(error);
        }
        if mask != 0 {
            self.codec_mask = mask;
        }
        Ok(())
    }

    /// Stop every stream and both command engines. Failure keeps ownership:
    /// DMA memory cannot be repurposed and the platform must reset the device.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.minimum_guard()?;
        // Only this invocation's RUN readbacks may establish quiescence.
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
                self.hdmi_note_descriptor_fault(index, fault);
                error.get_or_insert(fault);
            }
            if let Some(stream) = self.streams[usize::from(index)].as_mut() {
                stream.running = false;
                stream.poisoned = true;
            }
        }
        // Vendor amplifier effects follow stream-stop acknowledgements,
        // before command engines retire. A codec-control failure still permits
        // command-DMA quiescence, but is returned as a real incomplete shutdown.
        let codec_error = if error.is_none() {
            let mut error = self.shutdown_hdmi().err();
            if let Err(fault) = self.shutdown_realtek_codecs() {
                error.get_or_insert(fault);
            }
            if let Err(fault) = self.shutdown_conexant_codecs() {
                error.get_or_insert(fault);
            }
            if let Err(fault) = self.shutdown_sigmatel_codecs() {
                error.get_or_insert(fault);
            }
            if let Err(fault) = self.shutdown_cirrus_codecs() {
                error.get_or_insert(fault);
            }
            if let Err(fault) = self.shutdown_jack_notifications() {
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

impl<R, T> Drop for Controller<R, T> {
    fn drop(&mut self) {
        // No engine stop, unmap, reset or provider release is inferred in Drop.
        // Registers, timing and rings are ManuallyDrop; retain every dependent
        // codec/stream/GPU owner until the explicit drained extraction path.
        core::mem::forget(core::mem::take(&mut self.streams));
        core::mem::forget(core::mem::take(&mut self.routes));
        core::mem::forget(core::mem::take(&mut self.codec_controls));
        core::mem::forget(core::mem::take(&mut self.converter_bindings));
        core::mem::forget(core::mem::take(&mut self.realtek_codecs));
        core::mem::forget(core::mem::take(&mut self.conexant_codecs));
        core::mem::forget(core::mem::take(&mut self.sigmatel_codecs));
        core::mem::forget(core::mem::take(&mut self.cirrus_codecs));
        core::mem::forget(core::mem::take(&mut self.hdmi_ports));
    }
}

/// Check the entire device-visible extent, not its base. The caller has
/// already intersected identity/platform limits with GCAP's 32/64 flag.
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
mod tests;
