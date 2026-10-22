// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
// Copyright (C) 2019 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
//! Serialized polling boot/runtime mailbox over actual WFDMA TX/RX queues. Firmware
//! scatter needs real TX-DMA completion; acknowledged commands need both DMA
//! completion and an actual correctly sequenced MCU event. Timeout poisons the
//! complete mailbox epoch and retains owned queues/pins until controller reset.
use super::{
    download::{FailureKind, PortState, Transport, TransportFailure},
    firmware::{Prepared, Requests},
    identity::Identity,
    mcu::{self, Command, Encoder, Event, Queue},
    ring::{
        self, QueueIo, TxRing,
        rx::{Assembly, Frame, RxRing},
    },
};
use alloc::vec::Vec;

pub mod clc;
pub mod device;
pub mod eeprom;
pub mod firmware;
pub mod init;
pub mod key;

static NEXT_OWNER: crate::net::wifi::Identities = crate::net::wifi::Identities::new();

// Actual PCI send callbacks override the generic fill helper's 20*HZ with
// 3*HZ before the common MCU owner computes its response expiry.
const PCI_TIMEOUT_US: u64 = 3_000_000;
const MAX_EVENTS: usize = 64;
const MAX_EVENT_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    PendingTransmit,
    OwnerExhausted,
    ClockUnavailable,
    Ring(ring::Error),
    Message(mcu::Error),
    Timeout,
    EventLimit,
    CoreDump,
    CookieMismatch,
    Poisoned,
    FirmwareTarget,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Boot(Command),
    Unified(mcu::runtime::Command),
    Capabilities,
    Encapsulation,
    Clc,
    Domain,
    Power(mcu::power::Kind),
    Initial(mcu::init::Kind),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub command: Operation,
    pub sequence: u8,
    pub dma_released: bool,
    pub cause: Cause,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub command: Command,
    pub sequence: u8,
    pub result: u32,
    pub dma_released: bool,
    pub frame: Frame,
}
/// Actual UNI result plus real TX DMA completion. A nonzero status is an
/// explicit firmware rejection; it must never install a caller's context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnifiedReply {
    pub command: mcu::runtime::Command,
    pub sequence: u8,
    pub status: u32,
    pub dma_released: bool,
    pub frame: Frame,
}
/// Actual matched NIC-capability response, not a station-style status ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityReply {
    pub sequence: u8,
    pub dma_released: bool,
    pub frame: Frame,
}
/// Owned actual observations bound to the exact native command owner. This
/// receipt does not advertise radio modes or satisfy board/regulatory setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityReport {
    identity: Identity,
    owner: u64,
    reply: CapabilityReply,
    observed: mcu::capabilities::Capabilities,
}
impl CapabilityReport {
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn reply(&self) -> &CapabilityReply {
        &self.reply
    }
    pub fn observed(&self) -> &mcu::capabilities::Capabilities {
        &self.observed
    }
    /// Historical native owner binding only. The actual controller still
    /// validates live power/firmware/reset/port state and policy before use.
    pub fn belongs_to<W: QueueIo, F: QueueIo, R: QueueIo>(
        &self,
        mailbox: &Mailbox<W, F, R>,
    ) -> bool {
        self.owner == mailbox.owner
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityQueryFailure {
    Transport(TransportFailure),
    /// Command/response and real TX DMA completed. Preserve the actual owned
    /// raw response even though its capability body cannot be accepted.
    Malformed {
        error: mcu::capabilities::Error,
        reply: CapabilityReply,
    },
}
impl CapabilityQueryFailure {
    pub fn port(&self) -> PortState {
        match self {
            Self::Transport(e) => e.port,
            Self::Malformed { .. } => PortState::Usable,
        }
    }
}
impl core::fmt::Display for CapabilityQueryFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek capability query: {self:?}")
    }
}
impl core::error::Error for CapabilityQueryFailure {}
enum Packet {
    Boot(mcu::Packet),
    Unified(mcu::runtime::Packet),
    Capabilities(mcu::capabilities::Packet),
    Encapsulation(mcu::eeprom::Packet),
    Clc(mcu::clc::Packet),
    Domain(mcu::domain::Packet),
    Power(mcu::power::Packet),
    Initial(mcu::init::Packet),
}
impl Packet {
    fn operation(&self) -> Operation {
        match self {
            Self::Boot(p) => Operation::Boot(p.command),
            Self::Unified(p) => Operation::Unified(p.command()),
            Self::Capabilities(_) => Operation::Capabilities,
            Self::Encapsulation(_) => Operation::Encapsulation,
            Self::Clc(_) => Operation::Clc,
            Self::Domain(_) => Operation::Domain,
            Self::Power(p) => Operation::Power(p.kind()),
            Self::Initial(p) => Operation::Initial(p.kind()),
        }
    }
    fn sequence(&self) -> u8 {
        match self {
            Self::Boot(p) => p.sequence,
            Self::Unified(p) => p.sequence(),
            Self::Capabilities(p) => p.sequence(),
            Self::Encapsulation(p) => p.sequence(),
            Self::Clc(p) => p.sequence(),
            Self::Domain(p) => p.sequence(),
            Self::Power(p) => p.sequence(),
            Self::Initial(p) => p.sequence(),
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Boot(p) => &p.bytes,
            Self::Unified(p) => p.bytes(),
            Self::Capabilities(p) => p.bytes(),
            Self::Encapsulation(p) => p.bytes(),
            Self::Clc(p) => p.bytes(),
            Self::Domain(p) => p.bytes(),
            Self::Power(p) => p.bytes(),
            Self::Initial(p) => p.bytes(),
        }
    }
    fn queue(&self) -> Queue {
        match self {
            Self::Boot(p) => p.queue,
            Self::Domain(_) | Self::Power(_) | Self::Initial(_) => Queue::Wm,
            Self::Unified(_) | Self::Capabilities(_) | Self::Encapsulation(_) | Self::Clc(_) => {
                Queue::Wm
            }
        }
    }
    fn expects_response(&self) -> bool {
        match self {
            Self::Boot(p) => p.expects_response(),
            Self::Unified(_) | Self::Capabilities(_) | Self::Encapsulation(_) => true,
            Self::Clc(p) => p.completion() != super::firmware::clc::Completion::OneWay,
            Self::Domain(p) => p.expects_response(),
            Self::Power(p) => p.expects_response(),
            Self::Initial(p) => p.expects_response(),
        }
    }
    fn result(&self, event: &Event<'_>) -> Option<u32> {
        match self {
            Self::Boot(p) => event.boot_result(p).ok(),
            Self::Unified(p) => event.uni_result(p).ok().map(|r| r.status),
            Self::Capabilities(p) => event.capability_payload(p).ok().map(|_| 0),
            Self::Encapsulation(p) => event.encapsulation_payload(p).ok().map(|_| 0),
            Self::Clc(p) => event.clc_payload(p).ok().map(|_| 0),
            Self::Domain(p) => event.domain_payload(p).ok().map(|_| 0),
            Self::Power(p) => event.power_payload(p).ok().map(|_| 0),
            Self::Initial(p) => event.bootstrap_result(p).ok().map(|s| s.unwrap_or(0)),
        }
    }
}
#[derive(Clone, Copy)]
enum ReplySlot {
    Boot(usize),
    Unified,
    Capabilities,
    Encapsulation,
    Clc,
    Regulatory,
    Initial,
}

pub struct Mailbox<W: QueueIo, F: QueueIo, R: QueueIo> {
    identity: Identity,
    owner: u64,
    wm: TxRing<W>,
    fwdl: TxRing<F>,
    rx: RxRing<R>,
    runtime_rx: Option<RxRing<R>>,
    assembly: Assembly,
    runtime_assembly: Assembly,
    runtime_next: bool,
    encoder: Encoder,
    clock: crate::Clock,
    cookie: u64,
    poisoned: bool,
    last_failure: Option<Failure>,
    events: Vec<Frame>,
    event_bytes: usize,
    replies: Vec<Reply>,
    interrupted_unified_reply: Option<UnifiedReply>,
    interrupted_capability_reply: Option<CapabilityReply>,
    interrupted_encapsulation_reply: Option<eeprom::Reply>,
    interrupted_clc_reply: Option<clc::Reply>,
    interrupted_regulatory_reply: Option<clc::Reply>,
    download_binding: Option<firmware::Binding>,
    source_restart_cookie: Option<u64>,
    interrupted_initial_reply: Option<init::Reply>,
}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Mailbox<W, F, R> {
    /// # Safety
    /// All three actual queues must belong exclusively to this one actually
    /// observed identity/requester and the same coherent native DMA attachment.
    /// They must be the chip's WM/FWDL TX and WM event RX queues, configured by
    /// the owning controller with engines enabled, device IRQ sources masked,
    /// no competing command/NAPI/reset owners, and the actual calibrated Clock.
    /// Successful construction also requires an actual reset/fresh firmware
    /// command-sequencing epoch: every old command-processing path, old RX
    /// response, IRQ and deferred worker has drained, and no late response from
    /// a previous epoch can arrive. Empty TX queues alone cannot prove this.
    /// This constructor neither admits PCI ownership nor starts/resets hardware.
    pub unsafe fn from_rings(
        identity: Identity,
        wm: TxRing<W>,
        fwdl: TxRing<F>,
        rx: RxRing<R>,
        clock: crate::Clock,
    ) -> Result<Self, Cause> {
        if wm.pending() != 0 || fwdl.pending() != 0 {
            return Err(Cause::PendingTransmit);
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(Cause::ClockUnavailable);
        }
        let owner = NEXT_OWNER.next().ok_or(Cause::OwnerExhausted)?;
        Ok(Self {
            identity,
            owner,
            wm,
            fwdl,
            rx,
            runtime_rx: None,
            assembly: Assembly::default(),
            runtime_assembly: Assembly::default(),
            runtime_next: false,
            encoder: Encoder::default(),
            clock,
            cookie: 0,
            poisoned: false,
            last_failure: None,
            events: Vec::new(),
            event_bytes: 0,
            replies: Vec::new(),
            interrupted_unified_reply: None,
            interrupted_capability_reply: None,
            interrupted_encapsulation_reply: None,
            interrupted_clc_reply: None,
            interrupted_regulatory_reply: None,
            download_binding: None,
            source_restart_cookie: None,
            interrupted_initial_reply: None,
        })
    }
    /// # Safety
    /// All `from_rings` real requester/coherence/fresh sequencing conditions
    /// apply to every queue. `runtime_rx` is the same actual C2 requester's
    /// source post-download MCU/WA queue (WFDMA0+0x540), independently owned
    /// and posted before firmware can select it. No other consumer may poll,
    /// reset, release or assemble either event stream. This does not create a
    /// firmware epoch, install missing data queues or qualify a PCI claim.
    pub(super) unsafe fn from_rings_with_runtime_rx(
        identity: Identity,
        wm: TxRing<W>,
        fwdl: TxRing<F>,
        rx: RxRing<R>,
        runtime_rx: Option<RxRing<R>>,
        clock: crate::Clock,
    ) -> Result<Self, Cause> {
        if identity.chip == super::identity::Chip::Mt7925 && runtime_rx.is_some() {
            return Err(Cause::FirmwareTarget);
        }
        // SAFETY: covered by this function's own safety contract.
        let mut mailbox = unsafe { Self::from_rings(identity, wm, fwdl, rx, clock) }?;
        mailbox.runtime_rx = runtime_rx;
        Ok(mailbox)
    }
    pub(in crate::net::wifi::mediatek) fn receive_idle(&self) -> bool {
        self.assembly.is_idle() && self.runtime_assembly.is_idle() && self.events.is_empty()
    }
    pub fn last_failure(&self) -> Option<Failure> {
        self.last_failure
    }
    /// Unexpected/unsolicited frames are retained under explicit resource bounds.
    /// The caller dispatches them before radio/MLME continuation; none is silently
    /// consumed as an acknowledgement or dropped from a successful boot result.
    pub fn events(&self) -> &[Frame] {
        &self.events
    }
    /// Transfer retained actual asynchronous/unmatched frames to the owning
    /// controller for bounded dispatch. Their descriptor/drop evidence remains
    /// attached; removing them does not repair or reopen a poisoned epoch.
    pub fn take_events(&mut self) -> Vec<Frame> {
        self.event_bytes = 0;
        core::mem::take(&mut self.events)
    }
    /// Vendor lifecycle polling while no command is active. Complete actual
    /// frames retain per-stream assembly and bounded asynchronous ownership;
    /// they are not automatically classified as command ACKs or data packets.
    pub(in crate::net::wifi::mediatek) fn poll_events(&mut self) -> Result<Vec<Frame>, Cause> {
        if self.poisoned {
            return Err(Cause::Poisoned);
        }
        let result = (|| {
            for _ in 0..MAX_EVENTS {
                let Some(frame) = self.next_frame().map_err(Cause::Ring)? else {
                    break;
                };
                let core = Event::parse(self.identity.chip, &frame.bytes)
                    .is_ok_and(|e| e.event_id == 0xf0 || (e.option & 2 != 0 && e.event_id == 0x0a));
                self.retain(frame)?;
                if core {
                    return Err(Cause::CoreDump);
                }
            }
            Ok(())
        })();
        if let Err(cause) = result {
            self.poisoned = true;
            self.download_binding = None;
            self.source_restart_cookie = None;
            return Err(cause);
        }
        Ok(self.take_events())
    }
    pub fn replies(&self) -> &[Reply] {
        &self.replies
    }
    /// If an actual UNI ACK arrived before a later uncertain DMA/error, retain
    /// it for diagnosis. It does not authorize retry or context installation.
    pub fn interrupted_unified_reply(&self) -> Option<&UnifiedReply> {
        self.interrupted_unified_reply.as_ref()
    }
    pub fn interrupted_capability_reply(&self) -> Option<&CapabilityReply> {
        self.interrupted_capability_reply.as_ref()
    }
    /// Actual capability response plus real TX completion, with owned complete
    /// observations. This is not a usable radio/board/regulatory receipt.
    pub fn query_capabilities(&mut self) -> Result<CapabilityReport, CapabilityQueryFailure> {
        self.query_capabilities_timed(PCI_TIMEOUT_US)
    }
    fn query_capabilities_timed(
        &mut self,
        timeout_us: u64,
    ) -> Result<CapabilityReport, CapabilityQueryFailure> {
        if self.poisoned {
            return Err(CapabilityQueryFailure::Transport(self.failure(
                Operation::Capabilities,
                0,
                false,
                Cause::Poisoned,
            )));
        }
        let packet = self.encoder.encode_capabilities(self.identity.chip);
        self.execute(&Packet::Capabilities(packet), timeout_us)
            .map_err(CapabilityQueryFailure::Transport)?;
        let reply = self
            .interrupted_capability_reply
            .take()
            .expect("actual completed capability reply");
        // execute matched this exact chip/sequence event and retained its real
        // frame; parsing creates owned facts before this temporary view ends.
        let event =
            Event::parse(self.identity.chip, &reply.frame.bytes).expect("matched capability event");
        let observed =
            match mcu::capabilities::Capabilities::parse(self.identity.chip, event.payload) {
                Ok(observed) => observed,
                Err(error) => return Err(CapabilityQueryFailure::Malformed { error, reply }),
            };
        Ok(CapabilityReport {
            identity: self.identity,
            owner: self.owner,
            reply,
            observed,
        })
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn failure(
        &mut self,
        command: Operation,
        sequence: u8,
        dma_released: bool,
        cause: Cause,
    ) -> TransportFailure {
        self.poisoned = true;
        self.download_binding = None;
        self.source_restart_cookie = None;
        if self.last_failure.is_none() {
            self.last_failure = Some(Failure {
                command,
                sequence,
                dma_released,
                cause,
            });
        }
        TransportFailure {
            kind: if cause == Cause::Timeout {
                FailureKind::Timeout
            } else {
                FailureKind::InvalidResponse
            },
            port: PortState::Uncertain,
        }
    }
    fn retain(&mut self, frame: Frame) -> Result<(), Cause> {
        if self.events.len() == MAX_EVENTS || self.event_bytes + frame.bytes.len() > MAX_EVENT_BYTES
        {
            return Err(Cause::EventLimit);
        }
        self.event_bytes += frame.bytes.len();
        self.events.push(frame);
        Ok(())
    }
    fn next_frame(&mut self) -> Result<Option<Frame>, ring::Error> {
        if let Some(runtime) = self.runtime_rx.as_mut() {
            // Never concatenate fragments from two hardware queues. Alternate
            // complete-stream polls so a busy runtime queue cannot starve ROM
            // responses or vice versa across the actual firmware transition.
            for _ in 0..2 {
                let use_runtime = self.runtime_next;
                self.runtime_next = !self.runtime_next;
                let (queue, assembly) = if use_runtime {
                    (&mut *runtime, &mut self.runtime_assembly)
                } else {
                    (&mut self.rx, &mut self.assembly)
                };
                if let Some(fragment) = queue.poll()?
                    && let Some(frame) = assembly.push(fragment)?
                {
                    return Ok(Some(frame));
                }
            }
            return Ok(None);
        }
        let Some(fragment) = self.rx.poll()? else {
            return Ok(None);
        };
        self.assembly.push(fragment)
    }
    fn transfer(&mut self, command: Command, payload: &[u8]) -> Result<u32, TransportFailure> {
        self.transfer_timed(command, payload, PCI_TIMEOUT_US)
    }
    fn transfer_timed(
        &mut self,
        command: Command,
        payload: &[u8],
        timeout_us: u64,
    ) -> Result<u32, TransportFailure> {
        // A raw boot/download command may replace the actual firmware input.
        // Only the complete native wrapper may establish a new binding.
        self.download_binding = None;
        if self.poisoned {
            return Err(self.failure(Operation::Boot(command), 0, false, Cause::Poisoned));
        }
        let packet = self
            .encoder
            .encode(self.identity.chip, command, payload)
            .map_err(|_| TransportFailure {
                kind: FailureKind::InvalidResponse,
                port: PortState::Usable,
            })?;
        self.execute(&Packet::Boot(packet), timeout_us)
    }
    /// Execute an actual device/BSS/station UNI command using this existing
    /// owned WM/RX mailbox and sequence epoch. The body must be source-correct
    /// for the actual chip and retained caller generation. This does not infer
    /// a running radio, create a station or install a key from enqueue alone.
    /// Only a returned zero-status reply after actual RX and TX DMA completion
    /// can satisfy the command's firmware-acknowledgement dependency.
    pub fn unified(
        &mut self,
        command: mcu::runtime::Command,
        payload: &[u8],
    ) -> Result<UnifiedReply, TransportFailure> {
        self.unified_timed(command, payload, PCI_TIMEOUT_US)
    }
    fn unified_timed(
        &mut self,
        command: mcu::runtime::Command,
        payload: &[u8],
        timeout_us: u64,
    ) -> Result<UnifiedReply, TransportFailure> {
        if self.poisoned {
            return Err(self.failure(Operation::Unified(command), 0, false, Cause::Poisoned));
        }
        let packet = self
            .encoder
            .encode_uni(self.identity.chip, command, payload)
            .map_err(|_| TransportFailure {
                kind: FailureKind::InvalidResponse,
                port: PortState::Usable,
            })?;
        self.execute(&Packet::Unified(packet), timeout_us)?;
        Ok(self
            .interrupted_unified_reply
            .take()
            .expect("actual completed UNI reply"))
    }
    fn mark_dma_released(&mut self, slot: ReplySlot) {
        match slot {
            ReplySlot::Boot(i) => self.replies[i].dma_released = true,
            ReplySlot::Unified => {
                self.interrupted_unified_reply
                    .as_mut()
                    .expect("retained actual UNI reply")
                    .dma_released = true
            }
            ReplySlot::Capabilities => {
                self.interrupted_capability_reply
                    .as_mut()
                    .expect("retained actual capability reply")
                    .dma_released = true
            }
            ReplySlot::Encapsulation => {
                self.interrupted_encapsulation_reply
                    .as_mut()
                    .expect("retained actual EEPROM reply")
                    .dma_released = true
            }
            ReplySlot::Clc => {
                self.interrupted_clc_reply
                    .as_mut()
                    .expect("retained actual CLC reply")
                    .dma_released = true
            }
            ReplySlot::Initial => {
                self.interrupted_initial_reply
                    .as_mut()
                    .expect("retained actual initial reply")
                    .dma_released = true;
            }
            ReplySlot::Regulatory => {
                self.interrupted_regulatory_reply
                    .as_mut()
                    .expect("retained actual regulatory reply")
                    .dma_released = true;
            }
        }
    }
    fn execute(&mut self, packet: &Packet, timeout_us: u64) -> Result<u32, TransportFailure> {
        self.source_restart_cookie = None;
        let command = packet.operation();
        let sequence = packet.sequence();
        let Some(cookie) = self.cookie.checked_add(1) else {
            return Err(self.failure(command, sequence, false, Cause::CookieMismatch));
        };
        self.cookie = cookie;
        let submit = match packet.queue() {
            Queue::Wm => self.wm.submit(cookie, packet.bytes()),
            Queue::FirmwareDownload => self.fwdl.submit(cookie, packet.bytes()),
        };
        submit.map_err(|e| self.failure(command, sequence, false, Cause::Ring(e)))?;
        let deadline = self.clock.deadline(timeout_us);
        let mut dma_released = false;
        let mut reply: Option<(u32, ReplySlot)> = None;
        loop {
            if !dma_released {
                let completion = match packet.queue() {
                    Queue::Wm => self.wm.poll(),
                    Queue::FirmwareDownload => self.fwdl.poll(),
                }
                .map_err(|e| self.failure(command, sequence, false, Cause::Ring(e)))?;
                if let Some(completion) = completion {
                    if completion.cookie != cookie || completion.bytes != packet.bytes().len() {
                        return Err(self.failure(command, sequence, false, Cause::CookieMismatch));
                    }
                    dma_released = true;
                    if let Some((_, index)) = reply {
                        self.mark_dma_released(index);
                    }
                }
            }
            if let Some(frame) = self
                .next_frame()
                .map_err(|e| self.failure(command, sequence, dma_released, Cause::Ring(e)))?
            {
                if frame.drop {
                    self.retain(frame)
                        .map_err(|e| self.failure(command, sequence, dma_released, e))?;
                    return Err(self.failure(
                        command,
                        sequence,
                        dma_released,
                        Cause::Message(mcu::Error::NotResponse),
                    ));
                }
                let event = Event::parse(self.identity.chip, &frame.bytes);
                match event {
                    Ok(event)
                        if event.event_id == 0xf0
                            || (event.option & 2 != 0 && event.event_id == 0x0a) =>
                    {
                        self.retain(frame)
                            .map_err(|e| self.failure(command, sequence, dma_released, e))?;
                        return Err(self.failure(command, sequence, dma_released, Cause::CoreDump));
                    }
                    Ok(event) => match packet.result(&event) {
                        Some(result) if reply.is_none() => {
                            if matches!(command, Operation::Boot(_)) && self.replies.len() == 1024 {
                                return Err(self.failure(
                                    command,
                                    sequence,
                                    dma_released,
                                    Cause::EventLimit,
                                ));
                            }
                            let index = match command {
                                Operation::Boot(command) => {
                                    let index = self.replies.len();
                                    self.replies.push(Reply {
                                        command,
                                        sequence,
                                        result,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Boot(index)
                                }
                                Operation::Unified(command) => {
                                    self.interrupted_unified_reply = Some(UnifiedReply {
                                        command,
                                        sequence,
                                        status: result,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Unified
                                }
                                Operation::Capabilities => {
                                    self.interrupted_capability_reply = Some(CapabilityReply {
                                        sequence,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Capabilities
                                }
                                Operation::Encapsulation => {
                                    self.interrupted_encapsulation_reply = Some(eeprom::Reply {
                                        sequence,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Encapsulation
                                }
                                Operation::Clc => {
                                    self.interrupted_clc_reply = Some(clc::Reply {
                                        sequence,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Clc
                                }
                                Operation::Initial(kind) => {
                                    self.interrupted_initial_reply = Some(init::Reply {
                                        kind,
                                        sequence,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Initial
                                }
                                Operation::Domain | Operation::Power(_) => {
                                    self.interrupted_regulatory_reply = Some(clc::Reply {
                                        sequence,
                                        dma_released,
                                        frame,
                                    });
                                    ReplySlot::Regulatory
                                }
                            };
                            reply = Some((result, index));
                        }
                        _ => self
                            .retain(frame)
                            .map_err(|e| self.failure(command, sequence, dma_released, e))?,
                    },
                    Err(_) => self
                        .retain(frame)
                        .map_err(|e| self.failure(command, sequence, dma_released, e))?,
                }
            }
            if dma_released && (!packet.expects_response() || reply.is_some()) {
                if let Some((result, index)) = reply {
                    self.mark_dma_released(index);
                    return Ok(result);
                }
                return Ok(0);
            }
            if deadline.passed() {
                return Err(self.failure(command, sequence, dma_released, Cause::Timeout));
            }
            core::hint::spin_loop();
        }
    }
    /// # Safety
    /// The actual controller has acknowledged WFDMA idle/reset and drained every
    /// submission/IRQ/worker, including timed-out command processing, before any
    /// queue mapping is removed. A software timeout is never this proof.
    pub unsafe fn release_after_quiesce(&mut self) -> Result<(), ring::Error> {
        self.poisoned = true;
        self.download_binding = None;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            self.wm.release_after_quiesce()?;
            self.fwdl.release_after_quiesce()?;
            self.rx.release_after_quiesce()?
        };
        if let Some(runtime) = self.runtime_rx.as_mut() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { runtime.release_after_quiesce()? };
        }
        Ok(())
    }
}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Transport for Mailbox<W, F, R> {
    fn validate_firmware(&self, prepared: &Prepared<'_>) -> Result<(), TransportFailure> {
        if *prepared.requests() != Requests::new(&self.identity) {
            return Err(TransportFailure {
                kind: FailureKind::FirmwareTarget,
                port: PortState::Usable,
            });
        }
        Ok(())
    }
    fn command(&mut self, command: u8, payload: &[u8]) -> Result<u32, TransportFailure> {
        let command = Command::try_from(command).map_err(|_| TransportFailure {
            kind: FailureKind::InvalidResponse,
            port: PortState::Usable,
        })?;
        if command == Command::Scatter {
            return Err(TransportFailure {
                kind: FailureKind::InvalidResponse,
                port: PortState::Usable,
            });
        }
        self.transfer(command, payload)
    }
    fn scatter(&mut self, payload: &[u8]) -> Result<(), TransportFailure> {
        self.transfer(Command::Scatter, payload).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    mod clc;
    use super::super::{
        firmware::tests::{catalog, patch_bytes, ram_bytes},
        identity::{Chip, PciIdentity},
        ring::{
            rx::tests::device_receive,
            tests::{Domain, Io, Memory, Source, State, device_complete_one},
        },
    };
    use super::*;
    extern crate std;
    use alloc::sync::Arc;
    use std::sync::Mutex;
    struct Response {
        initial_execution: bool,
        client_execution: bool,
        roc_channel: Option<u8>,
        home_channel: Option<u8>,
        wrong_roc_token: bool,
        client_commands: Vec<Vec<u8>>,
        peers: alloc::collections::BTreeMap<u16, Vec<u8>>,
        receive_ba: alloc::collections::BTreeMap<(u16, u8), Vec<u8>>,
        initial_commands: Vec<Vec<u8>>,
        initial_fail_at: Option<usize>,
        raw_disabled: alloc::collections::BTreeSet<u16>,
        qualified_peer_slots: alloc::collections::BTreeSet<u16>,
        capability_payload: Option<Vec<u8>>,
        encapsulation_payload: Option<Vec<u8>>,
        capability_wrong_event: bool,
        require_firmware_start: bool,
        firmware_started: bool,
        device_execution: bool,
        device_active: bool,
        bss_active: bool,
        device_status: u32,
        bss_status: u32,
        key_execution: bool,
        keys: alloc::collections::BTreeMap<u8, Vec<u8>>,
        status: u32,
        command_delta: u8,
        event: u8,
        unsolicited: bool,
        drop: bool,
        pause_next_index_us: u64,
        patch_already_applied: bool,
        fail_firmware_start_publication: bool,
        clc_payload: Option<Vec<u8>>,
        clc_commands: Vec<Vec<u8>>,
        clc_guard: bool,
        clc_processing: bool,
        clc_no_reply_after: Option<usize>,
        clc_fail_publication_after: Option<usize>,
        clc_hide_tx_index: bool,
        regulatory_commands: Vec<Vec<u8>>,
        regulatory_domain: bool,
        regulatory_power: alloc::collections::BTreeMap<(u8, u8), Vec<u8>>,
        regulatory_no_reply_at: Option<usize>,
        regulatory_fail_publication_at: Option<usize>,
        regulatory_hide_tx_index_at: Option<usize>,
        regulatory_malformed_pse: bool,
        regulatory_expected_domain: Option<Vec<u8>>,
        regulatory_expected_power: alloc::collections::BTreeMap<(u8, u8), Vec<u8>>,
    }
    impl Default for Response {
        fn default() -> Self {
            Self {
                initial_execution: false,
                client_execution: false,
                roc_channel: None,
                home_channel: None,
                wrong_roc_token: false,
                client_commands: Vec::new(),
                peers: alloc::collections::BTreeMap::new(),
                receive_ba: alloc::collections::BTreeMap::new(),
                initial_commands: Vec::new(),
                initial_fail_at: None,
                raw_disabled: alloc::collections::BTreeSet::new(),
                qualified_peer_slots: alloc::collections::BTreeSet::new(),
                capability_payload: None,
                encapsulation_payload: None,
                capability_wrong_event: false,
                require_firmware_start: false,
                firmware_started: false,
                device_execution: false,
                device_active: false,
                bss_active: false,
                device_status: 0,
                bss_status: 0,
                key_execution: false,
                keys: alloc::collections::BTreeMap::new(),
                status: 0,
                command_delta: 0,
                event: 1,
                unsolicited: false,
                drop: false,
                pause_next_index_us: 0,
                patch_already_applied: false,
                fail_firmware_start_publication: false,
                clc_payload: None,
                clc_commands: Vec::new(),
                clc_guard: false,
                clc_processing: false,
                clc_no_reply_after: None,
                clc_fail_publication_after: None,
                clc_hide_tx_index: false,
                regulatory_commands: Vec::new(),
                regulatory_domain: false,
                regulatory_power: alloc::collections::BTreeMap::new(),
                regulatory_no_reply_at: None,
                regulatory_fail_publication_at: None,
                regulatory_hide_tx_index_at: None,
                regulatory_malformed_pse: false,
                regulatory_expected_domain: None,
                regulatory_expected_power: alloc::collections::BTreeMap::new(),
            }
        }
    }
    struct DeviceIo {
        io: Io,
        rx: Arc<Mutex<State>>,
        chip: Chip,
        reply: bool,
        wrong_seq: bool,
        delay: usize,
        polls: usize,
        pending_index: Option<u16>,
        fwdl: bool,
        response: Arc<Mutex<Response>>,
    }
    // SAFETY: one serialized model requester; actual model IOVA memory is read
    // before TX-index completion and actual RX IOVA bytes written before DDONE.
    unsafe impl QueueIo for DeviceIo {
        fn configure(&mut self, address: u32, count: u16) -> Result<(), ring::Error> {
            self.io.configure(address, count)
        }
        fn device_index(&mut self) -> Result<u16, ring::Error> {
            // submit probes the index before publication. Delay only an
            // actual published TX whose hardware index remains pending, so
            // the execute loop has already established its real deadline.
            let pause = if self.pending_index.is_some() {
                core::mem::take(&mut self.response.lock().unwrap().pause_next_index_us)
            } else {
                0
            };
            if pause != 0 {
                std::thread::sleep(std::time::Duration::from_micros(pause));
            }
            self.polls += 1;
            if self.polls >= self.delay
                && let Some(index) = self.pending_index.take()
            {
                self.io.0.lock().unwrap().index = index;
            }
            self.io.device_index()
        }
        fn publish(&mut self, head: u16) -> Result<(), ring::Error> {
            self.io.publish(head)?;
            let old = self.io.0.lock().unwrap().index;
            device_complete_one(&self.io.0);
            let packet = self.io.0.lock().unwrap().completed.last().unwrap().clone();
            if self.delay != 0 {
                self.pending_index = Some(self.io.0.lock().unwrap().index);
                self.io.0.lock().unwrap().index = old;
                self.polls = 0;
            }
            if !self.fwdl && self.reply {
                let unified = packet[43] & 2 != 0;
                let command = if unified { packet[34] } else { packet[36] };
                let seq = packet[39];
                let base = if self.chip == Chip::Mt7925 { 32 } else { 24 };
                if !unified && command == Command::StartFirmware as u8 {
                    let mut model = self.response.lock().unwrap();
                    model.firmware_started = true;
                    if model.fail_firmware_start_publication {
                        return Err(ring::Error::RegisterFailure);
                    }
                }
                let c3_power = unified && command == 0x2c && packet[52] == 1;
                if (unified && command == 0x15)
                    || (!unified && command == 0x0f)
                    || c3_power
                    || (!unified && (command == 0x5d || command == 0xc0))
                {
                    let mut model = self.response.lock().unwrap();
                    assert!(model.firmware_started && model.clc_guard && model.clc_processing);
                    let domain = command == 0x15 || command == 0x0f;
                    let pse = !unified && command == 0xc0;
                    let header = if unified { 48 } else { 64 };
                    let body = &packet[header..];
                    if domain {
                        assert_eq!(
                            body,
                            model
                                .regulatory_expected_domain
                                .as_ref()
                                .expect("actual retained model source domain")
                        );
                        model.regulatory_domain = true;
                    } else if !pse {
                        assert!(model.regulatory_domain);
                        let offset = if unified { 8 } else { 0 };
                        let n = body[offset + 4] as usize;
                        let band = body[offset + 5];
                        let start = if unified { 52 } else { 44 };
                        let stride = if unified { 450 } else { 162 };
                        assert_eq!(body.len(), start + n * stride);
                        for entry in body[start..].chunks_exact(stride) {
                            assert_eq!(
                                &entry[1..],
                                model
                                    .regulatory_expected_power
                                    .get(&(band, entry[0]))
                                    .expect("actual retained model source per-rate policy")
                            );
                            model
                                .regulatory_power
                                .insert((band, entry[0]), entry[1..].to_vec());
                        }
                    } else {
                        assert_eq!(body, &[0, 128, 12, 130, 0, 0, 0, 0]);
                    }
                    model.regulatory_commands.push(packet.clone());
                    let n = model.regulatory_commands.len();
                    if model.regulatory_hide_tx_index_at == Some(n) {
                        self.pending_index = Some(self.io.0.lock().unwrap().index);
                        self.io.0.lock().unwrap().index = old;
                        self.delay = usize::MAX;
                    }
                    if model.regulatory_fail_publication_at == Some(n) {
                        return Err(ring::Error::RegisterFailure);
                    }
                    if (!unified && !pse) || model.regulatory_no_reply_at == Some(n) {
                        return Ok(());
                    }
                    let payload: &[u8] = if pse {
                        if model.regulatory_malformed_pse {
                            &[0; 7]
                        } else {
                            &[0, 128, 12, 130, 0xde, 0xad, 0xbe, 0xef]
                        }
                    } else {
                        &[]
                    };
                    let mut response = vec![0; base + 12 + payload.len()];
                    response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                    response[base..base + 2]
                        .copy_from_slice(&((12 + payload.len()) as u16).to_le_bytes());
                    response[base + 4] = 0x55;
                    response[base + 5] = seq;
                    response[base + 6] = if unified { 2 } else { 0 };
                    response[base + 12..].copy_from_slice(payload);
                    device_receive(&self.rx, &response, true, 0);
                    return Ok(());
                }
                if (unified && command == 0x2c && packet[52] == 3) || (!unified && command == 0x5c)
                {
                    let mut model = self.response.lock().unwrap();
                    assert!(model.firmware_started && model.clc_guard);
                    // Firmware consumes the actual DMA-read bytes and may
                    // retain real policy/radio users before host publication
                    // reports success or any reply becomes observable.
                    model.clc_processing = true;
                    model.clc_commands.push(packet.clone());
                    let n = model.clc_commands.len();
                    if model.clc_hide_tx_index {
                        self.pending_index = Some(self.io.0.lock().unwrap().index);
                        self.io.0.lock().unwrap().index = old;
                        self.delay = usize::MAX;
                    }
                    if model.clc_fail_publication_after == Some(n) {
                        return Err(ring::Error::RegisterFailure);
                    }
                    let header = if unified { 48 } else { 64 };
                    let expects = unified || packet[header + 7] & 1 != 0;
                    if !expects || model.clc_no_reply_after == Some(n) {
                        return Ok(());
                    }
                    let body = model
                        .clc_payload
                        .as_ref()
                        .expect("actual modeled CLC response");
                    let mut response = vec![0; base + 12 + body.len()];
                    response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                    response[base..base + 2]
                        .copy_from_slice(&((12 + body.len()) as u16).to_le_bytes());
                    response[base + 4] = 0x55; // generic source parser: no invented EID or status
                    response[base + 5] = if self.wrong_seq { seq % 15 + 1 } else { seq };
                    response[base + 6] =
                        (if unified { 2 } else { 0 }) | if model.unsolicited { 4 } else { 0 };
                    response[base + 12..].copy_from_slice(body);
                    device_receive(
                        &self.rx,
                        &response,
                        true,
                        if model.drop { 1 << 14 } else { 0 },
                    );
                    return Ok(());
                }
                let initial = self.response.lock().unwrap().initial_execution
                    && ((!unified
                        && (command == 4
                            || command == 0xc5
                            || (command == 0xed
                                && matches!(packet[41], 0x21 | 0x3e | 0x46 | 0x4e | 5))))
                        || (unified
                            && (command == 0xb
                                || command == 0x27
                                || command == 8
                                || (command == 0x2d && packet[43] == 7))));
                if initial {
                    let mut model = self.response.lock().unwrap();
                    if command != 4 {
                        assert!(model.firmware_started && model.regulatory_domain);
                    }
                    model.initial_commands.push(packet.clone());
                    let n = model.initial_commands.len();
                    if model.initial_fail_at == Some(n) {
                        return Err(ring::Error::RegisterFailure);
                    }
                    if !unified
                        && (command == 4 || command == 0xc5 || (command == 0xed && packet[41] == 5))
                    {
                        return Ok(());
                    }
                    let mut response = vec![0; base + 12];
                    response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                    response[base..base + 2].copy_from_slice(&12u16.to_le_bytes());
                    response[base + 4] = 0x55;
                    response[base + 5] = seq;
                    response[base + 6] = if unified { 2 } else { 0 };
                    device_receive(&self.rx, &response, true, 0);
                    if command == 0x27 && model.client_execution {
                        let body = &packet[48..];
                        if body[4] == 0 {
                            assert_eq!(body.len(), 28);
                            assert_eq!(&body[4..8], &[0, 0, 24, 0]);
                            model.roc_channel = Some(body[10]);
                            let mut grant = vec![0; 68];
                            grant[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                            grant[36] = 0x27;
                            grant[38] = 6;
                            grant[50] = 20;
                            grant[52] = body[8];
                            grant[53] = body[9].wrapping_add(u8::from(model.wrong_roc_token));
                            grant[54] = 0xa5; // raw status is not inspected by source grant callback
                            grant[55] = body[10];
                            grant[57] = body[12];
                            grant[59] = body[14];
                            grant[61] = 0;
                            grant[62] = 0;
                            grant[64..68].copy_from_slice(&body[20..24]);
                            device_receive(&self.rx, &grant, true, 0);
                        } else {
                            assert_eq!(body.len(), 16);
                            model.roc_channel = None;
                        }
                    }
                    return Ok(());
                }
                let capability = (unified && command == 14) || (!unified && command == 0x8a);
                let encapsulation = (unified && command == 0x2d && packet[43] == 3)
                    || (!unified && command == 0xed && packet[41] == 1);
                if capability || encapsulation {
                    let model = self.response.lock().unwrap();
                    if model.require_firmware_start {
                        assert!(model.firmware_started);
                    }
                    let body = if encapsulation {
                        model
                            .encapsulation_payload
                            .as_ref()
                            .expect("actual modeled firmware EEPROM bytes")
                    } else {
                        model
                            .capability_payload
                            .as_ref()
                            .expect("actual modeled firmware capability bytes")
                    };
                    if encapsulation {
                        if self.chip == Chip::Mt7925 {
                            assert!(unified);
                            assert_eq!(packet[43], 3);
                            assert_eq!(
                                &packet[48..],
                                &[
                                    0, 0, 0, 0, 1, 0, 28, 0, 0x70, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                ]
                            );
                        } else {
                            assert!(!unified);
                            assert_eq!(packet[38], 0);
                            assert_eq!(packet[41], 1);
                            assert_eq!(packet[43], 1);
                            assert_eq!(
                                &packet[64..],
                                &[
                                    0x50, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0
                                ]
                            );
                        }
                    } else if self.chip == Chip::Mt7925 {
                        assert!(unified);
                        assert_eq!(packet[43], 6);
                        assert_eq!(&packet[48..], &[0, 0, 0, 0, 3, 0, 4, 0]);
                    } else {
                        assert!(!unified);
                        assert_eq!(packet.len(), 64);
                        assert_eq!(packet[38], 1);
                    }
                    let mut response = vec![0; base + 12 + body.len()];
                    response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                    response[base..base + 2]
                        .copy_from_slice(&((12 + body.len()) as u16).to_le_bytes());
                    response[base + 4] = if encapsulation {
                        0x55 // No invented EID=CID for either EEPROM helper.
                    } else if model.capability_wrong_event {
                        1
                    } else if self.chip == Chip::Mt7925 {
                        0x43
                    } else {
                        0x55
                    };
                    response[base + 5] = if self.wrong_seq { seq % 15 + 1 } else { seq };
                    response[base + 6] =
                        (if unified { 2 } else { 0 }) | if model.unsolicited { 4 } else { 0 };
                    response[base + 12..].copy_from_slice(body);
                    device_receive(
                        &self.rx,
                        &response,
                        true,
                        if model.drop { 1 << 14 } else { 0 },
                    );
                    return Ok(());
                }
                let mut response = vec![0u8; base + 12 + if unified { 8 } else { 0 }];
                response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                response[base..base + 2].copy_from_slice(&12u16.to_le_bytes());
                response[base + 4] = if command == 0x10 { 4 } else { 1 };
                response[base + 5] = if self.wrong_seq { seq % 15 + 1 } else { seq };
                response[base + 8] = if !unified && command == 0x10 {
                    if packet[64] == 1 {
                        if self.response.lock().unwrap().patch_already_applied {
                            1
                        } else {
                            2
                        }
                    } else {
                        3
                    }
                } else {
                    0
                };
                let mut drop = false;
                if unified {
                    assert_eq!(packet[35], 0);
                    assert_eq!(packet[37], 0xa0);
                    assert_eq!(packet[42], 0);
                    assert_eq!(packet[43], 7);
                    assert_eq!(
                        u16::from_le_bytes(packet[32..34].try_into().unwrap()) as usize,
                        packet.len() - 32
                    );
                    let mut model = self.response.lock().unwrap();
                    if model.initial_execution && !model.client_execution && command == 3 {
                        let body = &packet[48..];
                        assert!(model.device_active && model.bss_active);
                        if body[5] != 0xe {
                            assert!(
                                model.qualified_peer_slots.contains(&u16::from(body[1])),
                                "separately qualified peer owner required"
                            );
                        }
                        if self.chip == Chip::Mt7925 {
                            assert_eq!(body.len(), 16);
                            assert_eq!(&body[8..], [0x2b, 0, 8, 0, 0, 1, 1, 0]);
                        } else {
                            assert_eq!(body.len(), 28);
                            assert_eq!(&body[20..], [6, 0, 8, 0, 1, 0, 1, 0]);
                        }
                        model.raw_disabled.insert(u16::from(body[1]));
                        model.initial_commands.push(packet.clone());
                    }
                    if model.key_execution
                        && command == 3
                        && (!model.client_execution || packet.get(56) == Some(&0x27))
                    {
                        // Execute the actual DMA-read key body before ACK. A
                        // negative/absent ACK may still leave programmed state;
                        // tests must not infer atomic rejection from status.
                        let body = &packet[48..];
                        let (add, length, material) = if self.chip == Chip::Mt7925 {
                            assert_eq!(body.len(), 76);
                            assert_eq!(&body[8..12], &[0x27, 0, 68, 0]);
                            (body[12] == 1, body[25] as usize, 28)
                        } else {
                            assert_eq!(body.len(), 88);
                            assert_eq!(&body[8..10], &[17, 0]);
                            (body[12] == 0, body[19] as usize, 20)
                        };
                        if add {
                            model
                                .keys
                                .insert(body[1], body[material..material + length].to_vec());
                        } else {
                            model.keys.remove(&body[1]);
                        }
                    }
                    if model.client_execution {
                        model.client_commands.push(packet.clone());
                        if command == 2 && packet[52] == 0 && packet.len() > 84 {
                            let mut rest = &packet[52..];
                            while !rest.is_empty() {
                                let len =
                                    u16::from_le_bytes(rest[2..4].try_into().unwrap()) as usize;
                                if rest[0] == 2 {
                                    model.home_channel = Some(rest[4]);
                                }
                                rest = &rest[len..];
                            }
                        }
                        if command == 3 && packet.get(56) != Some(&0x27) {
                            let body = &packet[48..];
                            let slot = u16::from(body[1]);
                            if body[8] == 6 {
                                assert_eq!(body.len(), 24);
                                assert_eq!(&body[8..12], &[6, 0, 16, 0]);
                                assert_eq!(body[13], 2); // actual recipient direction
                                assert_eq!(body[14], 0); // source RX_START params.amsdu
                                let tid = body[12];
                                if body[15] == 0 {
                                    model.receive_ba.remove(&(slot, tid));
                                } else {
                                    assert_eq!(body[15], 1 << tid);
                                    model.receive_ba.insert((slot, tid), body.to_vec());
                                }
                            } else if body[8] == 0x25 {
                                model.peers.remove(&slot);
                                model.raw_disabled.remove(&slot);
                            } else {
                                let last = &body[body.len() - 8..];
                                assert_eq!(last, &[0x2b, 0, 8, 0, 0, 1, 1, 0]);
                                model.peers.insert(slot, body.to_vec());
                                model.raw_disabled.insert(slot);
                            }
                        }
                    }
                    let status = if model.device_execution && (command == 1 || command == 2) {
                        let body = &packet[48..];
                        if command == 1 {
                            assert_eq!(body.len(), 16);
                            assert_eq!(&body[4..8], &[0, 0, 12, 0]);
                            model.device_active = body[8] != 0;
                            model.device_status
                        } else {
                            if !model.client_execution || body[4] == 0 {
                                assert!(body.len() == 36 || model.client_execution);
                                assert_eq!(&body[4..8], &[0, 0, 32, 0]);
                                model.bss_active = body[8] != 0;
                            }
                            model.bss_status
                        }
                    } else {
                        model.status
                    };
                    response[base + 4] = model.event;
                    response[base + 6] = 2 | if model.unsolicited { 4 } else { 0 };
                    response[base + 12] = command.wrapping_add(model.command_delta);
                    response[base + 16..base + 20].copy_from_slice(&status.to_le_bytes());
                    drop = model.drop;
                }
                device_receive(&self.rx, &response, true, if drop { 1 << 14 } else { 0 });
            }
            Ok(())
        }
    }
    fn identity(chip: Chip) -> Identity {
        let id = match chip {
            Chip::Mt7921 => 0x7961,
            Chip::Mt7922 => 0x7922,
            Chip::Mt7925 => 0x7925,
        };
        Identity::observed(
            PciIdentity {
                vendor: 0x14c3,
                device: id,
                subsystem_vendor: 0x1234,
                subsystem_device: 0xabcd,
                revision: 3,
            },
            u32::from(id),
            0x12340010,
            Some(0),
        )
        .unwrap()
    }
    type TestMailbox = Mailbox<DeviceIo, DeviceIo, Io>;
    type ModelState = Arc<Mutex<State>>;
    fn setup(
        chip: Chip,
        reply: bool,
        wrong_seq: bool,
        delay: usize,
    ) -> (TestMailbox, ModelState, ModelState, ModelState) {
        setup_controlled(
            chip,
            reply,
            wrong_seq,
            delay,
            Arc::new(Mutex::new(Response::default())),
        )
    }
    fn model_clock() -> crate::Clock {
        static CLOCK: std::sync::OnceLock<crate::Clock> = std::sync::OnceLock::new();
        *CLOCK.get_or_init(|| {
            // The model uses live RDTSC, so its Clock must convert the actual
            // host ticks to microseconds. A fixture value of1 collapsed the
            // real PCI3s deadline to about1ms and failed under scheduling load.
            // Sample once for this local model, never per-command/suite-wide.
            let ticks = crate::Clock::ticks();
            let start = std::time::Instant::now();
            std::thread::sleep(std::time::Duration::from_millis(2));
            let elapsed = start.elapsed().as_nanos();
            let elapsed_ticks = crate::Clock::ticks().wrapping_sub(ticks);
            crate::Clock {
                ticks_per_microsecond: u64::try_from(
                    (u128::from(elapsed_ticks) * 1_000).div_ceil(elapsed),
                )
                .unwrap()
                .max(1),
            }
        })
    }
    fn setup_controlled(
        chip: Chip,
        reply: bool,
        wrong_seq: bool,
        delay: usize,
        response: Arc<Mutex<Response>>,
    ) -> (TestMailbox, ModelState, ModelState, ModelState) {
        // One real modeled requester/domain has one shared IOVA namespace.
        // Queue register states remain independent; all device DMA resolves
        // through this same registry and allocator.
        let memory = Arc::new(Mutex::new(Memory::default()));
        let domain: Arc<dyn crate::bus::dma::mapping::DmaDomain> = Arc::new(Domain(memory.clone()));
        let wm = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let fwdl = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let rx = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let alloc_tx = |state: Arc<Mutex<State>>, is_fwdl| {
            unsafe {
                TxRing::install(
                    DeviceIo {
                        io: Io(state.clone()),
                        rx: rx.clone(),
                        chip,
                        reply,
                        wrong_seq,
                        delay,
                        polls: 0,
                        pending_index: None,
                        fwdl: is_fwdl,
                        response: response.clone(),
                    },
                    &Source,
                    domain.clone(),
                    8,
                )
            }
            .unwrap()
        };
        let wmring = alloc_tx(wm.clone(), false);
        let fwring = alloc_tx(fwdl.clone(), true);
        let rxring =
            unsafe { RxRing::install(Io(rx.clone()), &Source, domain.clone(), 8) }.unwrap();
        {
            let bases = [
                wm.lock().unwrap().base,
                fwdl.lock().unwrap().base,
                rx.lock().unwrap().base,
            ];
            let memory = memory.lock().unwrap();
            assert_eq!(memory.mappings.len(), 27);
            let mut last_end = 0;
            let mut cpu = alloc::collections::BTreeSet::new();
            for (&address, (pins, pointer, _direction)) in &memory.mappings {
                assert!(address >= last_end);
                last_end = address + pins.bytes() as u64;
                assert!(cpu.insert(*pointer));
            }
            assert_ne!(bases[0], bases[1]);
            assert_ne!(bases[0], bases[2]);
            assert_ne!(bases[1], bases[2]);
        }
        // SAFETY: all queues are exclusively owned parts of this one modeled chip;
        // clock is a live RDTSC test boundary and all firmware events use real IOVAs.
        let m =
            unsafe { Mailbox::from_rings(identity(chip), wmring, fwring, rxring, model_clock()) }
                .unwrap();
        (m, wm, fwdl, rx)
    }
    #[test]
    fn full_prepared_download_uses_real_tx_and_rx_iova_memory_for_every_chip() {
        use super::super::download::{Downloader, PatchState, ReleaseState};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let (mailbox, wm, fwdl, rx) = setup(chip, true, false, 0);
            let requests = Requests::new(&identity(chip));
            let provider = catalog(&requests, patch_bytes(), ram_bytes());
            let prepared = requests.load(&provider).unwrap();
            let mut engine = Downloader::new(mailbox);
            let report = engine.download(&prepared).unwrap();
            assert_eq!(report.patch, PatchState::Uploaded);
            assert_eq!(report.release, ReleaseState::Released);
            assert!(report.firmware_start_acknowledged);
            assert_eq!(wm.lock().unwrap().completed.len(), 6);
            assert_eq!(fwdl.lock().unwrap().completed.len(), 2);
            assert_eq!(engine.transport().replies().len(), 6);
            if chip == Chip::Mt7922 {
                let mut mailbox = engine.into_transport();
                // SAFETY: actual modeled controller is stopped before teardown.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
                drop(mailbox);
                assert!(
                    wm.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
                assert!(
                    fwdl.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
                assert!(
                    rx.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
            } else {
                // Owned domains/pins remain live if the composed downloader
                // is dropped before acknowledged controller quiescence.
                drop(engine);
                assert!(wm.lock().unwrap().memory.lock().unwrap().mappings.len() >= 2);
                assert!(rx.lock().unwrap().memory.lock().unwrap().mappings.len() >= 2);
            }
        }
    }
    #[test]
    fn actual_ack_does_not_release_tx_memory_before_hardware_dma_index() {
        let (mut m, wm, _, _) = setup(Chip::Mt7925, true, false, 3);
        assert_eq!(m.command(0x10, &1u32.to_le_bytes()), Ok(2));
        assert_eq!(wm.lock().unwrap().index, 1);
        assert_eq!(m.replies().len(), 1);
        assert!(m.replies()[0].dma_released);
        assert_eq!(m.wm.pending(), 0);
        assert_eq!(
            wm.lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .syncs
                .iter()
                .filter(|v| v.0)
                .count(),
            4
        );
        // SAFETY: explicit model stop covers every live TX/RX queue.
        unsafe { m.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn host_scheduling_delay_preserves_real_deadline_but_expiry_keeps_actual_ownership() {
        for expire in [false, true] {
            let response = Arc::new(Mutex::new(Response {
                pause_next_index_us: 10_000,
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(Chip::Mt7922, true, false, 3, response);
            let result = mailbox.unified_timed(
                mcu::runtime::Command::StationRecord,
                &[0; 8],
                if expire { 0 } else { PCI_TIMEOUT_US },
            );
            if expire {
                assert_eq!(result.unwrap_err().port, PortState::Uncertain);
                let failure = mailbox.last_failure().unwrap();
                assert_eq!(failure.cause, Cause::Timeout);
                assert!(!failure.dma_released);
                assert!(mailbox.is_poisoned());
                assert_eq!(mailbox.wm.pending(), 1);
                let reply = mailbox.interrupted_unified_reply().unwrap();
                assert!(!reply.dma_released);
                assert_eq!(reply.status, 0);
                {
                    let mut registers = wm.lock().unwrap();
                    registers.index = registers.head;
                }
                assert!(
                    mailbox
                        .unified(mcu::runtime::Command::StationRecord, &[0; 8])
                        .is_err()
                );
                assert_eq!(mailbox.last_failure(), Some(failure));
                assert_eq!(mailbox.wm.pending(), 1);
                assert_eq!(wm.lock().unwrap().completed.len(), 1);
            } else {
                let reply = result.unwrap();
                assert!(reply.dma_released);
                assert_eq!(reply.status, 0);
                assert!(!mailbox.is_poisoned());
                assert_eq!(mailbox.wm.pending(), 0);
                assert!(mailbox.interrupted_unified_reply().is_none());
            }
            // SAFETY: actual modeled requester/firmware/all deferred users stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn boot_and_runtime_share_real_dma_sequence_and_return_runtime_ack_ownership() {
        use super::super::{download::Downloader, mcu::runtime::Command as Uni};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let response = Arc::new(Mutex::new(Response::default()));
            let (mailbox, wm, _, _) = setup_controlled(chip, true, false, 3, response.clone());
            let requests = Requests::new(&identity(chip));
            let provider = catalog(&requests, patch_bytes(), ram_bytes());
            let prepared = requests.load(&provider).unwrap();
            let mut downloader = Downloader::new(mailbox);
            downloader.download(&prepared).unwrap();
            let mut mailbox = downloader.into_transport();
            let mut sequence = wm.lock().unwrap().completed.last().unwrap()[39];
            assert_eq!(mailbox.replies().len(), 6);
            for n in 0..1100u32 {
                let status = if n % 97 == 0 { 0x80000001 } else { 0 };
                response.lock().unwrap().status = status;
                let command = match n % 3 {
                    0 => Uni::DeviceInfo,
                    1 => Uni::BssInfo,
                    _ => Uni::StationRecord,
                };
                // Opaque command payload semantics remain outside this transport
                // model. It actually reads/publishes the canonical DMA bytes.
                let reply = mailbox.unified(command, &[n as u8; 8]).unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(reply.sequence, sequence);
                assert_eq!(reply.command, command);
                assert_eq!(reply.status, status);
                assert!(reply.dma_released);
                assert!(!reply.frame.drop);
                assert!(mailbox.interrupted_unified_reply().is_none());
                assert_eq!(mailbox.replies().len(), 6);
                assert_eq!(mailbox.wm.pending(), 0);
                assert!(!mailbox.is_poisoned()); // actual known firmware rejection is usable
                let packet = wm.lock().unwrap().completed.last().unwrap().clone();
                assert_eq!(packet[39], sequence);
                assert_eq!(packet[34], command as u8);
                assert_eq!(&packet[48..], &[n as u8; 8]);
            }
            assert_eq!(mailbox.command(0x10, &1u32.to_le_bytes()), Ok(2));
            assert_eq!(
                wm.lock().unwrap().completed.last().unwrap()[39],
                sequence % 15 + 1
            );
            // SAFETY: modeled firmware/requester and all queues are stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
            assert!(
                wm.lock()
                    .unwrap()
                    .memory
                    .lock()
                    .unwrap()
                    .mappings
                    .is_empty()
            );
        }
    }
    #[test]
    fn unmatched_dropped_and_late_runtime_responses_never_acknowledge_a_context() {
        use super::super::mcu::runtime::Command as Uni;
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..8 {
                let response = Arc::new(Mutex::new(Response::default()));
                match case {
                    2 => response.lock().unwrap().command_delta = 1,
                    3 => response.lock().unwrap().event = 2,
                    4 => response.lock().unwrap().unsolicited = true,
                    5 => response.lock().unwrap().drop = true,
                    6 => {
                        let mut r = response.lock().unwrap();
                        r.event = 0x0a;
                        r.unsolicited = true;
                    }
                    _ => {}
                }
                let (mut mailbox, wm, _, _) = setup_controlled(
                    chip,
                    case != 0,
                    case == 1,
                    if case == 7 { usize::MAX } else { 0 },
                    response,
                );
                let error = mailbox
                    .unified_timed(Uni::StationRecord, &[0; 8], 0)
                    .unwrap_err();
                assert_eq!(error.port, PortState::Uncertain);
                assert!(mailbox.is_poisoned());
                let failure = mailbox.last_failure().unwrap();
                assert_eq!(failure.command, Operation::Unified(Uni::StationRecord));
                assert_eq!(
                    failure.cause,
                    match case {
                        5 => Cause::Message(mcu::Error::NotResponse),
                        6 => Cause::CoreDump,
                        _ => Cause::Timeout,
                    }
                );
                if case == 7 {
                    let actual = mailbox
                        .interrupted_unified_reply()
                        .expect("actual early ACK retained");
                    assert!(!actual.dma_released);
                    assert_eq!(actual.command, Uni::StationRecord);
                    assert_eq!(actual.status, 0);
                } else {
                    assert!(mailbox.interrupted_unified_reply().is_none());
                }
                let count = wm.lock().unwrap().completed.len();
                wm.lock().unwrap().index = 1;
                assert!(mailbox.unified(Uni::StationRecord, &[0; 8]).is_err());
                assert!(mailbox.command(0x10, &[0; 4]).is_err());
                assert_eq!(mailbox.last_failure(), Some(failure));
                assert_eq!(wm.lock().unwrap().completed.len(), count);
                // SAFETY: explicit modeled reset drains even the late firmware ACK.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn invalid_runtime_payload_is_usable_but_uncertain_publication_is_not() {
        use super::super::mcu::runtime::Command as Uni;
        let (mut mailbox, wm, _, _) = setup(Chip::Mt7925, true, false, 0);
        let error = mailbox.unified(Uni::StationRecord, &[0; 7]).unwrap_err();
        assert_eq!(error.port, PortState::Usable);
        assert!(!mailbox.is_poisoned());
        assert!(wm.lock().unwrap().completed.is_empty());
        assert_eq!(
            mailbox
                .unified(Uni::StationRecord, &[0; 8])
                .unwrap()
                .sequence,
            1
        );
        wm.lock().unwrap().fail_publish = true;
        assert_eq!(
            mailbox
                .unified(Uni::StationRecord, &[0; 8])
                .unwrap_err()
                .port,
            PortState::Uncertain
        );
        assert!(mailbox.is_poisoned());
        assert_eq!(mailbox.wm.pending(), 1);
        assert_eq!(wm.lock().unwrap().completed.len(), 1);
        // SAFETY: actual modeled function reset has stopped uncertain publication.
        unsafe { mailbox.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn actual_asynchronous_events_transfer_for_dispatch_without_becoming_runtime_ack() {
        use super::super::mcu::runtime::Command as Uni;
        let (mut mailbox, _, _, rx) = setup(Chip::Mt7925, true, false, 0);
        for n in 0..100u32 {
            let mut actual = vec![0; 48];
            actual[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
            actual[36] = 0x27;
            actual[38] = 6;
            actual[44..48].copy_from_slice(&n.to_le_bytes());
            device_receive(&rx, &actual, true, 0);
            let reply = mailbox.unified(Uni::BssInfo, &[0; 8]).unwrap();
            assert_eq!(reply.status, 0);
            assert!(reply.dma_released);
            let events = mailbox.take_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].bytes, actual);
            assert!(!events[0].drop);
            assert!(mailbox.events().is_empty());
            assert_eq!(mailbox.event_bytes, 0);
        }
        unsafe { mailbox.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn missing_or_stale_reply_poison_epoch_and_keep_first_failure_after_late_completion() {
        for (reply, wrong, delay) in [
            (false, false, 0),
            (true, true, 0),
            (true, false, usize::MAX),
        ] {
            let (mut m, wm, _, _) = setup(Chip::Mt7921, reply, wrong, delay);
            let err = m
                .transfer_timed(Command::PatchSemaphore, &1u32.to_le_bytes(), 0)
                .unwrap_err();
            assert_eq!(err.kind, FailureKind::Timeout);
            assert_eq!(err.port, PortState::Uncertain);
            assert!(m.is_poisoned());
            let original = m.last_failure().unwrap();
            let count = wm.lock().unwrap().completed.len();
            if wrong {
                assert_eq!(m.events().len(), 1);
            }
            if delay == usize::MAX {
                assert_eq!(m.replies().len(), 1);
                assert!(!m.replies()[0].dma_released);
            }
            // A late actual DMA-index completion never opens a poisoned mailbox epoch.
            wm.lock().unwrap().index = 1;
            assert!(m.command(0x10, &[0; 4]).is_err());
            assert_eq!(m.last_failure(), Some(original));
            assert_eq!(wm.lock().unwrap().completed.len(), count);
            // SAFETY: controller reset owner explicitly stopped all model DMA now.
            unsafe { m.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn exact_firmware_target_is_checked_before_the_first_mcu_command() {
        use super::super::download::{Downloader, Stage};
        let (m, wm, fwdl, _) = setup(Chip::Mt7922, true, false, 0);
        let wrong = Requests::new(&identity(Chip::Mt7921));
        let provider = catalog(&wrong, patch_bytes(), ram_bytes());
        let prepared = wrong.load(&provider).unwrap();
        let mut downloader = Downloader::new(m);
        let error = downloader.download(&prepared).unwrap_err();
        assert_eq!(error.stage, Stage::FirmwareTarget);
        assert_eq!(error.failure.kind, FailureKind::FirmwareTarget);
        assert_eq!(error.failure.port, PortState::Usable);
        assert!(wm.lock().unwrap().completed.is_empty());
        assert!(fwdl.lock().unwrap().completed.is_empty());
    }
    #[test]
    fn actual_core_dump_event_is_retained_and_refuses_even_a_later_valid_ack() {
        for (eid, option) in [(0xf0, 0), (0x0a, 6)] {
            let (mut m, _, _, rx) = setup(Chip::Mt7925, true, false, 0);
            let mut event = vec![0u8; 44];
            event[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
            event[32..34].copy_from_slice(&12u16.to_le_bytes());
            event[36] = eid;
            event[37] = 1;
            event[38] = option;
            device_receive(&rx, &event, true, 0);
            assert!(m.command(0x10, &1u32.to_le_bytes()).is_err());
            assert_eq!(m.last_failure().unwrap().cause, Cause::CoreDump);
            assert_eq!(m.events()[0].bytes, event);
            assert!(m.replies().is_empty());
            // SAFETY: explicit controller stop/reset covers pending later ACK.
            unsafe { m.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    #[ignore = "requires pinned firmware and unchanged donor download trace fixtures"]
    fn actual_pinned_download_crosses_owned_dma_and_actual_mcu_event_path() {
        use super::super::download::Downloader;
        use sha2::{Digest, Sha256};
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        let oracle = std::path::PathBuf::from(std::env::var("STELA_MT792X_ORACLE").unwrap());
        for (chip, number, hash) in [
            (
                Chip::Mt7921,
                7921,
                "3d6d7aaa078980259c08e04467ac500ca57735887ffd2a66d60d3da1f28bb458",
            ),
            (
                Chip::Mt7922,
                7922,
                "a7796d0533de77419ee5925ad4c0060f3dbbd58ae02086ac106af9f56c8015aa",
            ),
            (
                Chip::Mt7925,
                7925,
                "1903493fa3e5b5fb058924b0529f35b5cd646e036486275cde074fade4d78146",
            ),
        ] {
            let expected = std::fs::read(oracle.join(alloc::format!("{number}.trace"))).unwrap();
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&expected)), hash);
            let (m, wm, fwdl, rx) = setup(chip, true, false, 0);
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            let mut downloader = Downloader::new(m);
            assert!(
                downloader
                    .download(&prepared)
                    .unwrap()
                    .firmware_start_acknowledged
            );
            let wm = wm.lock().unwrap();
            let fw = fwdl.lock().unwrap();
            let (mut at, mut wi, mut fi, mut operation) = (0usize, 0usize, 0usize, 0usize);
            while at < expected.len() {
                let cmd = expected[at];
                let n = u32::from_le_bytes(expected[at + 2..at + 6].try_into().unwrap()) as usize;
                let bytes = &expected[at + 6..at + 6 + n];
                if cmd == 0xee {
                    assert_eq!(fw.completed[fi], bytes);
                    fi += 1;
                } else {
                    let packet = &wm.completed[wi];
                    wi += 1;
                    assert_eq!(packet[36], cmd);
                    assert_eq!(packet[39], (operation % 15 + 1) as u8);
                    assert_eq!(&packet[64..], bytes);
                }
                operation += 1;
                at += 6 + n;
            }
            assert_eq!(wi, wm.completed.len());
            assert_eq!(fi, fw.completed.len());
            drop(wm);
            drop(fw);
            assert!(
                rx.lock()
                    .unwrap()
                    .memory
                    .lock()
                    .unwrap()
                    .syncs
                    .iter()
                    .any(|v| v.0)
            );
        }
    }
    #[test]
    fn pending_old_request_and_same_sequence_ack_refuse_new_mailbox_epoch() {
        for old_fwdl in [false, true] {
            let (m, wm_state, fwdl_state, rx_state) = setup(Chip::Mt7921, true, false, 0);
            let Mailbox {
                identity,
                mut wm,
                mut fwdl,
                rx,
                clock,
                ..
            } = m;
            let old = Encoder::default()
                .encode(Chip::Mt7921, Command::PatchSemaphore, &1u32.to_le_bytes())
                .unwrap();
            if old_fwdl {
                fwdl.submit(1, &old.bytes).unwrap();
            } else {
                wm.submit(1, &old.bytes).unwrap();
            }
            // Simulate old RX sequence1 even when the pending queue is FWDL.
            if old_fwdl {
                let mut response = vec![0u8; 36];
                response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                response[29] = 1;
                response[32] = 2;
                device_receive(&rx_state, &response, true, 0);
            }
            // This constructor must reject known pending TX before assuming
            // the caller's otherwise-required fresh firmware-epoch proof.
            let result = unsafe { Mailbox::from_rings(identity, wm, fwdl, rx, clock) };
            assert!(matches!(result, Err(Cause::PendingTransmit)));
            assert_eq!(
                wm_state.lock().unwrap().completed.len(),
                usize::from(!old_fwdl)
            );
            assert_eq!(
                fwdl_state.lock().unwrap().completed.len(),
                usize::from(old_fwdl)
            );
            assert_eq!(wm_state.lock().unwrap().queue_drops, 0);
            assert_eq!(rx_state.lock().unwrap().queue_drops, 0);
        }
    }
    struct KeyResource(Arc<core::sync::atomic::AtomicUsize>);
    impl Drop for KeyResource {
        fn drop(&mut self) {
            self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    fn key_context() -> super::super::mcu::key::Context {
        super::super::mcu::key::Context {
            bss_index: 2,
            omac_index: 3,
            station_disabled: false,
        }
    }
    fn key_scope(group: bool) -> crate::net::wifi::security::KeyScope {
        use crate::net::{Mac, wifi::security::KeyScope};
        if group {
            KeyScope::Group(Mac([2, 6, 7, 8, 9, 10]))
        } else {
            KeyScope::Pairwise(Mac([2, 1, 2, 3, 4, 5]))
        }
    }
    fn key_packet(
        key: crate::net::wifi::security::KeyIdentity,
        pn: u64,
    ) -> crate::net::wifi::frame::Mpdu {
        use crate::net::wifi::{
            Band, RadioStatus, RawRate,
            frame::Mpdu,
            security::{Integrity, PacketNumber, SecurityStatus},
        };
        let mut bytes = vec![0; 27];
        bytes[..2].copy_from_slice(&0x4008u16.to_le_bytes());
        bytes[24..].copy_from_slice(&[1, 2, 3]);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-40),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 1,
                    words: [0; 4],
                },
                tsf: None,
            },
            SecurityStatus {
                key: Some(key),
                pn: PacketNumber::new(pn),
                decrypted: true,
                integrity: Integrity::Verified,
                iv_stripped: true,
                mic_stripped: true,
                ..SecurityStatus::default()
            },
        )
        .unwrap()
    }
    #[test]
    fn canonical_keys_require_actual_dma_ack_and_removed_users_drain() {
        use crate::net::wifi::security::{Cipher, Error as Sec, ReplaySeed};
        use key::{Error as KeyError, HardwareKey};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for group in [false, true] {
                let response = Arc::new(Mutex::new(Response {
                    key_execution: true,
                    ..Response::default()
                }));
                let (mut mailbox, wm, _, _) =
                    setup_controlled(chip, true, false, 4, response.clone());
                let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
                // SAFETY: owned empty modeled WCID/actual BSS, with no old users.
                let mut key = unsafe {
                    HardwareKey::claim(
                        &mailbox,
                        7,
                        key_context(),
                        key_scope(group),
                        KeyResource(drops.clone()),
                    )
                }
                .unwrap();
                let mut last_generation = 0;
                for (n, cipher) in [
                    Cipher::Ccmp128,
                    Cipher::Ccmp256,
                    Cipher::Gcmp128,
                    Cipher::Gcmp256,
                ]
                .into_iter()
                .enumerate()
                {
                    let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                        16
                    } else {
                        32
                    };
                    let material = vec![(n + 1) as u8; length];
                    let index = if group { 2 } else { 0 };
                    let installed = key
                        .install(
                            &mut mailbox,
                            index,
                            cipher,
                            &material,
                            ReplaySeed::uniform(
                                crate::net::wifi::security::PacketNumber::new(7).unwrap(),
                            ),
                        )
                        .unwrap();
                    assert_eq!(key.slot().installed(), Some(installed));
                    assert!(installed.generation() > last_generation);
                    last_generation = installed.generation();
                    assert_eq!(response.lock().unwrap().keys.get(&7), Some(&material));
                    assert!(key.last_reply().unwrap().dma_released);
                    assert!(matches!(
                        key.authorize(&key_packet(installed, 7)),
                        Err(Sec::Replay)
                    ));
                    assert!(key.authorize(&key_packet(installed, 123)).is_ok());
                    let published = wm.lock().unwrap().completed.len();
                    let identity = key
                        .install(&mut mailbox, index, cipher, &material, ReplaySeed::ZERO)
                        .unwrap();
                    assert_eq!(identity, installed);
                    assert!(matches!(
                        key.authorize(&key_packet(installed, 123)),
                        Err(Sec::Replay)
                    ));
                    assert!(key.authorize(&key_packet(installed, 124)).is_ok());
                    assert_eq!(wm.lock().unwrap().completed.len(), published);
                    let receipt = key.remove(&mut mailbox).unwrap();
                    assert!(key.slot().installed().is_none());
                    assert!(key.needs_drain());
                    assert!(response.lock().unwrap().keys.is_empty());
                    assert_eq!(
                        key.install(&mut mailbox, index, cipher, &material, ReplaySeed::ZERO),
                        Err(KeyError::NeedsDrain)
                    );
                    assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
                    // SAFETY: model key table is actually empty and old modeled
                    // RX/TX/deferred users for this key have been drained.
                    unsafe { key.retire_after_drain(receipt) }.unwrap();
                }
                drop(key);
                assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 1);
                // SAFETY: actual modeled requester/firmware and all queues stopped.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn uncertain_key_programming_retains_actual_resource_and_canonical_candidate() {
        use crate::net::wifi::security::{Cipher, ReplaySeed};
        use key::HardwareKey;
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..6 {
                let response = Arc::new(Mutex::new(Response {
                    key_execution: true,
                    ..Response::default()
                }));
                match case {
                    0 => response.lock().unwrap().status = 0x80000001,
                    1 => response.lock().unwrap().command_delta = 1,
                    2 => response.lock().unwrap().unsolicited = true,
                    3 => response.lock().unwrap().drop = true,
                    _ => (),
                }
                let (mut mailbox, wm, _, _) = setup_controlled(
                    chip,
                    true,
                    false,
                    if case == 4 { usize::MAX } else { 0 },
                    response.clone(),
                );
                let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
                // SAFETY: owned empty modeled WCID/BSS, no previous key users.
                let mut key = unsafe {
                    HardwareKey::claim(
                        &mailbox,
                        7,
                        key_context(),
                        key_scope(false),
                        KeyResource(drops.clone()),
                    )
                }
                .unwrap();
                if case == 5 {
                    wm.lock().unwrap().fail_publish = true;
                }
                assert!(
                    key.install(&mut mailbox, 0, Cipher::Ccmp128, &[9; 16], ReplaySeed::ZERO)
                        .is_err()
                );
                assert!(key.slot().installed().is_none());
                assert!(key.is_quarantined());
                if case != 5 {
                    assert_eq!(response.lock().unwrap().keys.get(&7), Some(&vec![9; 16]));
                }
                if case == 4 {
                    assert_eq!(key.last_reply().unwrap().status, 0);
                    assert!(!key.last_reply().unwrap().dma_released);
                }
                let count = wm.lock().unwrap().completed.len();
                assert!(
                    key.install(&mut mailbox, 0, Cipher::Ccmp128, &[9; 16], ReplaySeed::ZERO)
                        .is_err()
                );
                assert_eq!(wm.lock().unwrap().completed.len(), count);
                // A nonzero firmware status is not proof that material was
                // unused. A subsequent successful remove still needs real drain.
                if case == 0 {
                    response.lock().unwrap().status = 0;
                    let receipt = key.remove(&mut mailbox).unwrap();
                    // SAFETY: actual modeled key removal and all old users drained.
                    unsafe { key.retire_after_drain(receipt) }.unwrap();
                    // As in Linux, the removed slot accepts the key again.
                    assert!(
                        key.install(&mut mailbox, 0, Cipher::Ccmp128, &[9; 16], ReplaySeed::ZERO)
                            .is_ok()
                    );
                }
                drop(key);
                assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
                // SAFETY: actual modeled requester reset drains all late DMA/ACK.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn native_key_owner_refuses_cross_mailbox_and_stale_removal_receipts() {
        use crate::net::wifi::security::{Cipher, ReplaySeed};
        use key::{Error as KeyError, HardwareKey};
        let (mut a, awm, _, _) = setup(Chip::Mt7921, true, false, 0);
        let (mut b, bwm, _, _) = setup(Chip::Mt7921, true, false, 0);
        // SAFETY: two independently owned empty modeled physical slots.
        let mut first =
            unsafe { HardwareKey::claim(&a, 7, key_context(), key_scope(false), ()) }.unwrap();
        let mut second =
            unsafe { HardwareKey::claim(&a, 8, key_context(), key_scope(false), ()) }.unwrap();
        assert_eq!(
            first.install(&mut b, 0, Cipher::Ccmp128, &[1; 16], ReplaySeed::ZERO),
            Err(KeyError::WrongMailbox)
        );
        assert!(first.slot().installed().is_none());
        assert!(bwm.lock().unwrap().completed.is_empty());
        first
            .install(&mut a, 0, Cipher::Ccmp128, &[1; 16], ReplaySeed::ZERO)
            .unwrap();
        second
            .install(&mut a, 0, Cipher::Ccmp128, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        let one = first.remove(&mut a).unwrap();
        let two = second.remove(&mut a).unwrap();
        // SAFETY: old modeled users drained, but deliberately wrong receipt
        // must still be rejected rather than allowing another key to retire.
        assert_eq!(
            unsafe { first.retire_after_drain(two) },
            Err(KeyError::WrongRemoval)
        );
        assert!(first.needs_drain());
        // SAFETY: correct actual modeled receipt and old users are drained.
        unsafe { first.retire_after_drain(one) }.unwrap();
        assert_eq!(awm.lock().unwrap().completed.len(), 4);
        // Deliberately leave second Removed: Drop must retain its actual owner
        // until its own old-user drain proof, never infer drain from the ACK.
        // SAFETY: both independent modeled requester queues actually stopped.
        unsafe { a.release_after_quiesce() }.unwrap();
        unsafe { b.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn failed_removal_invalidates_and_retains_the_actual_station_until_real_drain() {
        use crate::net::wifi::security::{Cipher, ReplaySeed};
        use key::HardwareKey;
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..4 {
                let response = Arc::new(Mutex::new(Response {
                    key_execution: true,
                    ..Response::default()
                }));
                let (mut mailbox, wm, _, _) =
                    setup_controlled(chip, true, false, 0, response.clone());
                let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
                // SAFETY: one exclusively owned empty modeled WCID/BSS.
                let mut key = unsafe {
                    HardwareKey::claim(
                        &mailbox,
                        7,
                        key_context(),
                        key_scope(false),
                        KeyResource(drops.clone()),
                    )
                }
                .unwrap();
                key.install(&mut mailbox, 0, Cipher::Ccmp128, &[5; 16], ReplaySeed::ZERO)
                    .unwrap();
                match case {
                    0 => response.lock().unwrap().status = 1,
                    1 => response.lock().unwrap().command_delta = 1,
                    2 => wm.lock().unwrap().fail_publish = true,
                    _ => (),
                }
                let result = key.remove(&mut mailbox);
                if case == 3 {
                    assert!(result.is_ok());
                    assert!(key.needs_drain());
                    // Deliberately withhold actual old-user drain/receipt use.
                } else {
                    assert!(result.is_err());
                    assert!(key.is_quarantined());
                    assert!(!key.needs_drain());
                }
                assert!(key.slot().installed().is_none());
                drop(key);
                assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
                // SAFETY: actual modeled hardware reset stops all old key users.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    fn initial_context(chip: Chip, bss: u8) -> super::super::mcu::device::Context {
        super::super::mcu::device::Context {
            bss_index: bss,
            omac_index: bss,
            band_index: if chip == Chip::Mt7925 { 0xff } else { 0 },
            wmm_index: bss,
            link_index: 0,
            broadcast_wcid: if chip == Chip::Mt7925 {
                19 - u16::from(bss)
            } else {
                0
            },
            address: crate::net::Mac([2, 1, 2, 3, 4, bss]),
        }
    }
    #[test]
    fn native_initial_interface_requires_both_real_commands_and_later_user_drain() {
        use device::{Disposition, Interface, Step};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let response = Arc::new(Mutex::new(Response {
                device_execution: true,
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(chip, true, false, 4, response.clone());
            let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
            let context = initial_context(chip, 0);
            // SAFETY: actual modeled source-correct exclusive interface/context
            // resources, unregistered with all previous users drained.
            let mut interface =
                unsafe { Interface::claim(&mailbox, context, KeyResource(drops.clone())) }.unwrap();
            assert!(interface.registered_context().is_none());
            interface.activate(&mut mailbox).unwrap();
            assert_eq!(interface.registered_context(), Some(context));
            assert!(response.lock().unwrap().device_active);
            assert!(response.lock().unwrap().bss_active);
            assert_eq!(
                interface
                    .replies()
                    .iter()
                    .map(|r| r.step)
                    .collect::<Vec<_>>(),
                vec![Step::ActivateDevice, Step::ActivateBss]
            );
            assert!(interface.activate(&mut mailbox).is_err());
            let receipt = interface.deactivate(&mut mailbox).unwrap();
            assert!(interface.registered_context().is_none());
            assert!(interface.needs_drain());
            assert!(!response.lock().unwrap().device_active);
            assert!(!response.lock().unwrap().bss_active);
            assert_eq!(
                interface
                    .replies()
                    .iter()
                    .map(|r| r.step)
                    .collect::<Vec<_>>(),
                vec![
                    Step::ActivateDevice,
                    Step::ActivateBss,
                    Step::DeactivateBss,
                    Step::DeactivateDevice
                ]
            );
            assert!(
                interface
                    .replies()
                    .iter()
                    .all(|r| r.raw.dma_released && r.disposition == Disposition::Accepted)
            );
            assert_eq!(
                wm.lock()
                    .unwrap()
                    .completed
                    .iter()
                    .map(|p| p[34])
                    .collect::<Vec<_>>(),
                vec![1, 2, 2, 1]
            );
            assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
            // SAFETY: both actual modeled contexts inactive and all old firmware,
            // key, DMA, IRQ and deferred consumers now drained.
            unsafe { interface.retire_after_drain(receipt) }.unwrap();
            drop(interface);
            assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 1);
            // SAFETY: actual modeled requester/firmware and queues stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn partial_initial_registration_or_uncertain_publication_retains_actual_contexts() {
        use device::{Disposition, Interface};
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..7 {
                let response = Arc::new(Mutex::new(Response {
                    device_execution: true,
                    ..Response::default()
                }));
                match case {
                    0 => response.lock().unwrap().device_status = 1,
                    1 => response.lock().unwrap().bss_status = 1,
                    2 => response.lock().unwrap().command_delta = 1,
                    3 => response.lock().unwrap().unsolicited = true,
                    4 => response.lock().unwrap().drop = true,
                    _ => (),
                }
                let (mut mailbox, wm, _, _) = setup_controlled(
                    chip,
                    true,
                    false,
                    if case == 5 { usize::MAX } else { 0 },
                    response.clone(),
                );
                let drops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
                // SAFETY: exclusive initially unregistered modeled resources.
                let mut interface = unsafe {
                    Interface::claim(
                        &mailbox,
                        initial_context(chip, 0),
                        KeyResource(drops.clone()),
                    )
                }
                .unwrap();
                if case == 6 {
                    wm.lock().unwrap().fail_publish = true;
                }
                assert!(interface.activate(&mut mailbox).is_err());
                assert!(interface.registered_context().is_none());
                assert!(interface.is_quarantined());
                if case < 6 {
                    assert!(response.lock().unwrap().device_active);
                }
                if case == 1 {
                    assert!(response.lock().unwrap().bss_active);
                }
                let published = wm.lock().unwrap().completed.len();
                assert!(interface.activate(&mut mailbox).is_err());
                assert_eq!(wm.lock().unwrap().completed.len(), published);
                if case < 2 {
                    assert_eq!(
                        interface.replies().last().unwrap().disposition,
                        Disposition::Rejected
                    );
                    // The usable real command port may perform one actual
                    // reverse-order cleanup, but it still cannot prove drain.
                    response.lock().unwrap().device_status = 0;
                    response.lock().unwrap().bss_status = 0;
                    let _receipt = interface.deactivate(&mut mailbox).unwrap();
                    assert!(interface.needs_drain());
                }
                if case == 5 {
                    assert_eq!(interface.interrupted_reply().unwrap().status, 0);
                    assert!(!interface.interrupted_reply().unwrap().dma_released);
                }
                drop(interface);
                assert_eq!(drops.load(core::sync::atomic::Ordering::Relaxed), 0);
                // SAFETY: explicit actual modeled reset drains all late users.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn source_already_inactive_applies_only_to_actual_bss_deactivation() {
        use device::{Disposition, Error as Dev, Interface};
        for case in 0..4 {
            let response = Arc::new(Mutex::new(Response {
                device_execution: true,
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) =
                setup_controlled(Chip::Mt7925, true, false, 0, response.clone());
            // SAFETY: exclusive initially unregistered modeled interface context.
            let mut interface =
                unsafe { Interface::claim(&mailbox, initial_context(Chip::Mt7925, 0), ()) }
                    .unwrap();
            if case < 2 {
                if case == 0 {
                    response.lock().unwrap().device_status = 0xc0000001;
                } else {
                    response.lock().unwrap().bss_status = 0xc0000001;
                }
                assert!(matches!(
                    interface.activate(&mut mailbox),
                    Err(Dev::Firmware {
                        status: 0xc0000001,
                        ..
                    })
                ));
            } else {
                interface.activate(&mut mailbox).unwrap();
                if case == 2 {
                    response.lock().unwrap().bss_status = 0xc0000001;
                } else {
                    response.lock().unwrap().device_status = 0xc0000001;
                }
                let result = interface.deactivate(&mut mailbox);
                if case == 2 {
                    let receipt = result.unwrap();
                    let reply = &interface.replies()[2];
                    assert_eq!(reply.disposition, Disposition::AlreadyInactive);
                    assert_eq!(reply.raw.status, 0xc0000001); // never rewritten as0
                    assert_eq!(interface.replies().len(), 4);
                    // SAFETY: actual modeled contexts inactive, all users drained.
                    unsafe { interface.retire_after_drain(receipt) }.unwrap();
                } else {
                    assert!(matches!(
                        result,
                        Err(Dev::Firmware {
                            status: 0xc0000001,
                            ..
                        })
                    ));
                    assert!(interface.deactivate(&mut mailbox).is_err());
                }
            }
            let published = wm.lock().unwrap().completed.len();
            assert_eq!(
                published,
                if case == 0 {
                    1
                } else if case == 1 {
                    2
                } else {
                    4
                }
            );
            // SAFETY: actual modeled requester and late firmware users stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn initial_owner_private_receipt_and_actual_resource_survive_wrong_controller_and_drop() {
        use device::{Error as Dev, Interface};
        let (mut a, awm, _, _) = setup(Chip::Mt7921, true, false, 0);
        let (mut b, bwm, _, _) = setup(Chip::Mt7921, true, false, 0);
        let adrops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let bdrops = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        // SAFETY: independent actual modeled requesters and exclusive resources.
        let mut first = unsafe {
            Interface::claim(
                &a,
                initial_context(Chip::Mt7921, 0),
                KeyResource(adrops.clone()),
            )
        }
        .unwrap();
        let mut second = unsafe {
            Interface::claim(
                &b,
                initial_context(Chip::Mt7921, 0),
                KeyResource(bdrops.clone()),
            )
        }
        .unwrap();
        assert_eq!(first.activate(&mut b), Err(Dev::WrongMailbox));
        assert!(awm.lock().unwrap().completed.is_empty());
        assert!(bwm.lock().unwrap().completed.is_empty());
        first.activate(&mut a).unwrap();
        second.activate(&mut b).unwrap();
        let own = first.deactivate(&mut a).unwrap();
        let other = second.deactivate(&mut b).unwrap();
        // SAFETY: actual modeled old users drained, but wrong requester receipt
        // must still be rejected rather than retiring a different actual owner.
        assert_eq!(
            unsafe { first.retire_after_drain(other) },
            Err(Dev::WrongReceipt)
        );
        assert!(first.needs_drain());
        // SAFETY: exact correct receipt and actual modeled old-user drain.
        unsafe { first.retire_after_drain(own) }.unwrap();
        drop(first);
        drop(second); // deliberately no valid retirement proof for second
        assert_eq!(adrops.load(core::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(bdrops.load(core::sync::atomic::Ordering::Relaxed), 0);
        // SAFETY: actual modeled requesters/firmware/queues now stopped.
        unsafe { a.release_after_quiesce() }.unwrap();
        unsafe { b.release_after_quiesce() }.unwrap();
        assert_eq!(bdrops.load(core::sync::atomic::Ordering::Relaxed), 0);
    }
    fn capability_bytes(chip: Chip, n: u8) -> Vec<u8> {
        let phy = [1, 1, 1, 0, 1 + n % 2, 0, 1, 1, 0, 0, 3, 1, 1];
        let mut bytes = vec![5, 0, 0xa5, 0x5a];
        for (tag, body) in [
            (7u32, &[2, 1, 2, 3, 4, n][..]),
            (8, &phy[..if chip == Chip::Mt7925 { 13 } else { 12 }]),
            (0x18, &[0]),
            (0x20, &[n, 1, 2, 3, 4, 5, 6, 7]),
            (0xbeef, &[9, 8, n]),
        ] {
            if chip == Chip::Mt7925 {
                bytes.extend_from_slice(&(tag as u16).to_le_bytes());
                bytes.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
            } else {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            }
            bytes.extend_from_slice(body);
        }
        bytes.extend_from_slice(&[0x31, 0x32]);
        bytes
    }
    #[test]
    fn actual_capability_queries_share_runtime_sequence_and_bind_owned_raw_facts() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let response = Arc::new(Mutex::new(Response {
                capability_payload: Some(capability_bytes(chip, 0)),
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(chip, true, false, 3, response.clone());
            let (mut other, _, _, _) = setup(chip, true, false, 0);
            let mut sequence = 0;
            for n in 0..100u32 {
                let body = capability_bytes(chip, n as u8);
                response.lock().unwrap().capability_payload = Some(body.clone());
                let report = mailbox.query_capabilities().unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(report.reply().sequence, sequence);
                assert!(report.reply().dma_released);
                assert!(report.belongs_to(&mailbox));
                assert!(!report.belongs_to(&other));
                assert_eq!(report.identity(), identity(chip));
                assert_eq!(report.observed().raw(), body);
                assert_eq!(
                    report.observed().mac(),
                    Some(crate::net::Mac([2, 1, 2, 3, 4, n as u8]))
                );
                assert_eq!(report.observed().trailing(), &[0x31, 0x32]);
                assert!(mailbox.interrupted_capability_reply().is_none());
                let reply = mailbox
                    .unified(mcu::runtime::Command::StationRecord, &[0; 8])
                    .unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(reply.sequence, sequence);
                assert_eq!(wm.lock().unwrap().completed.len(), (2 * (n + 1)) as usize);
            }
            // SAFETY: both actual modeled requesters and queues now stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
            unsafe { other.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn malformed_completed_capability_body_returns_actual_owned_frame_without_port_poison() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for body in [vec![], vec![1, 0, 0, 0], vec![1, 4, 0, 0]] {
                let response = Arc::new(Mutex::new(Response {
                    capability_payload: Some(body.clone()),
                    ..Response::default()
                }));
                let (mut mailbox, _, _, _) =
                    setup_controlled(chip, true, false, 0, response.clone());
                let failure = mailbox.query_capabilities().unwrap_err();
                assert_eq!(failure.port(), PortState::Usable);
                let CapabilityQueryFailure::Malformed { reply, .. } = failure else {
                    panic!("completed malformed report is not a transport timeout")
                };
                assert!(reply.dma_released);
                let event = Event::parse(chip, &reply.frame.bytes).unwrap();
                assert_eq!(event.payload, body);
                assert!(!mailbox.is_poisoned());
                assert!(mailbox.last_failure().is_none());
                response.lock().unwrap().capability_payload = Some(capability_bytes(chip, 1));
                assert!(mailbox.query_capabilities().is_ok());
                // SAFETY: actual modeled requester/firmware and queues stopped.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn uncertain_capability_response_retains_early_reply_and_closes_same_epoch() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..6 {
                if case == 2 && chip != Chip::Mt7925 {
                    continue;
                }
                let response = Arc::new(Mutex::new(Response {
                    capability_payload: Some(capability_bytes(chip, 2)),
                    ..Response::default()
                }));
                match case {
                    2 => response.lock().unwrap().capability_wrong_event = true,
                    3 => response.lock().unwrap().unsolicited = true,
                    4 => response.lock().unwrap().drop = true,
                    _ => (),
                }
                let (mut mailbox, wm, _, _) = setup_controlled(
                    chip,
                    case != 0,
                    case == 1,
                    if case == 5 { usize::MAX } else { 0 },
                    response,
                );
                let failure = mailbox.query_capabilities_timed(0).unwrap_err();
                assert_eq!(failure.port(), PortState::Uncertain);
                assert!(matches!(failure, CapabilityQueryFailure::Transport(_)));
                assert!(mailbox.is_poisoned());
                assert_eq!(
                    mailbox.last_failure().unwrap().command,
                    Operation::Capabilities
                );
                if case == 5 {
                    let reply = mailbox.interrupted_capability_reply().unwrap();
                    assert!(!reply.dma_released);
                    assert_eq!(reply.sequence, 1);
                }
                let count = wm.lock().unwrap().completed.len();
                wm.lock().unwrap().index = 1;
                assert!(mailbox.query_capabilities().is_err());
                assert!(
                    mailbox
                        .unified(mcu::runtime::Command::StationRecord, &[0; 8])
                        .is_err()
                );
                assert_eq!(wm.lock().unwrap().completed.len(), count);
                // SAFETY: actual modeled reset drains all late command/DMA users.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    #[ignore = "requires pinned firmware and unchanged NIC parser reports"]
    fn actual_pinned_firmware_and_linux_capability_reports_cross_native_dma_query() {
        use super::super::download::Downloader;
        let images = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_FIRMWARE").expect("firmware images"),
        );
        let oracle = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_CAPABILITIES_ORACLE")
                .expect("source capability reports"),
        );
        for (chip, number) in [
            (Chip::Mt7921, "7921"),
            (Chip::Mt7922, "7922"),
            (Chip::Mt7925, "7925"),
        ] {
            let trace = std::fs::read(oracle.join(alloc::format!("{number}.trace"))).unwrap();
            let response = Arc::new(Mutex::new(Response {
                capability_payload: Some(vec![]),
                require_firmware_start: true,
                ..Response::default()
            }));
            let (mailbox, wm, _, _) = setup_controlled(chip, true, false, 2, response.clone());
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            let mut downloader = Downloader::new(mailbox);
            assert!(
                downloader
                    .download(&prepared)
                    .unwrap()
                    .firmware_start_acknowledged
            );
            let mut mailbox = downloader.into_transport();
            let mut cursor = 0;
            let count = wm.lock().unwrap().completed.len();
            for _ in 0..1024 {
                let n = usize::from(u16::from_le_bytes(
                    trace[cursor..cursor + 2].try_into().unwrap(),
                ));
                cursor += 2;
                let body = &trace[cursor..cursor + n];
                cursor += n;
                let expected = &trace[cursor..cursor + 22];
                cursor += 22;
                response.lock().unwrap().capability_payload = Some(body.to_vec());
                let report = mailbox.query_capabilities().unwrap();
                assert!(report.reply().dma_released);
                assert!(report.belongs_to(&mailbox));
                assert_eq!(report.observed().raw(), body);
                assert_eq!(
                    report.observed().mac().unwrap_or(crate::net::Mac([0; 6])).0,
                    expected[..6]
                );
                assert_eq!(
                    report.observed().chip_flags().unwrap_or(0).to_le_bytes(),
                    expected[12..20]
                );
            }
            assert_eq!(cursor, trace.len());
            assert_eq!(wm.lock().unwrap().completed.len(), count + 1024);
            // SAFETY: actual modeled requester/firmware/all queues now stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }

    #[test]
    #[ignore = "requires freshly generated unchanged PCI send-callback oracle"]
    fn actual_pci_callbacks_select_three_second_deadline_and_exact_queue() {
        let oracle =
            std::path::PathBuf::from(std::env::var("STELA_MT792X_PCI_MCU_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let trace = std::fs::read(oracle.join(alloc::format!("{number}.trace"))).unwrap();
            let mut cursor = 0;
            let mut encoder = Encoder::default();
            for i in 0..90 {
                let header = &trace[cursor..cursor + 12];
                cursor += 12;
                let profile = header[0];
                let ticks = u32::from_le_bytes(header[4..8].try_into().unwrap());
                // Oracle HZ=1000; this is effective post-fill timeout, not the
                // generic writer's intermediate value. No real-time sleep.
                assert_eq!(u64::from(ticks) * 1_000, PCI_TIMEOUT_US);
                let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
                let wire = &trace[cursor..cursor + length];
                cursor += length;
                assert_eq!(profile, (i / 6 % 3) as u8);
                let (sequence, queue, encoded) = match profile {
                    0 => {
                        let command = Command::try_from(header[1]).unwrap();
                        let body = if command == Command::Scatter {
                            wire
                        } else {
                            &wire[64..]
                        };
                        let packet = encoder.encode(chip, command, body).unwrap();
                        (packet.sequence, packet.queue, packet.bytes)
                    }
                    1 => {
                        let command = match header[1] {
                            1 => mcu::runtime::Command::DeviceInfo,
                            2 => mcu::runtime::Command::BssInfo,
                            3 => mcu::runtime::Command::StationRecord,
                            _ => panic!("unexpected UNI source command"),
                        };
                        let packet = encoder.encode_uni(chip, command, &wire[48..]).unwrap();
                        (packet.sequence(), mcu::Queue::Wm, packet.bytes().to_vec())
                    }
                    2 => {
                        let packet = encoder.encode_capabilities(chip);
                        (packet.sequence(), mcu::Queue::Wm, packet.bytes().to_vec())
                    }
                    _ => panic!("unexpected source profile"),
                };
                assert_eq!(sequence, header[2]);
                assert_eq!(header[3], u8::from(queue == mcu::Queue::FirmwareDownload));
                assert_eq!(encoded, wire);
            }
            assert_eq!(cursor, trace.len());
        }
    }

    fn eeprom_body(chip: Chip, value: u8) -> Vec<u8> {
        let c3 = chip == Chip::Mt7925;
        let mut body = vec![0; if c3 { 80 } else { 24 }];
        let at = if c3 { 12 } else { 0 };
        body[at..at + 4].copy_from_slice(&(if c3 { 0xa70u32 } else { 0x550 }).to_le_bytes());
        body[if c3 { 49 } else { 19 }] = value;
        body
    }
    #[test]
    fn native_encapsulation_read_keeps_exact_owner_raw_byte_and_shared_sequence() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let response = Arc::new(Mutex::new(Response {
                encapsulation_payload: Some(eeprom_body(chip, 0)),
                capability_payload: Some(capability_bytes(chip, 0)),
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(chip, true, false, 3, response.clone());
            let (mut other, _, _, _) = setup(chip, true, false, 0);
            let mut sequence = 0;
            for value in 0..=255 {
                let body = eeprom_body(chip, value);
                response.lock().unwrap().encapsulation_payload = Some(body.clone());
                let report = mailbox.query_encapsulation().unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(report.reply().sequence, sequence);
                assert!(report.reply().dma_released);
                assert!(report.belongs_to(&mailbox));
                assert!(!report.belongs_to(&other));
                assert_eq!(report.identity(), identity(chip));
                assert_eq!(report.observed().raw(), body);
                assert_eq!(report.observed().byte(), value);
                assert_eq!(report.observed().raw_valid(), 0);
                assert!(mailbox.interrupted_encapsulation_reply().is_none());
                let cap = mailbox.query_capabilities().unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(cap.reply().sequence, sequence);
                let uni = mailbox
                    .unified(mcu::runtime::Command::StationRecord, &[0; 8])
                    .unwrap();
                sequence = sequence % 15 + 1;
                assert_eq!(uni.sequence, sequence);
            }
            assert_eq!(wm.lock().unwrap().completed.len(), 768);
            // SAFETY: actual modeled controllers/firmware/all queue users stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
            unsafe { other.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn malformed_completed_eeprom_read_retains_raw_frame_without_default_board_byte() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut wrong = eeprom_body(chip, 0xff);
            wrong[if chip == Chip::Mt7925 { 12 } else { 0 }] ^= 16;
            for body in [vec![], vec![0; 8], wrong] {
                let response = Arc::new(Mutex::new(Response {
                    encapsulation_payload: Some(body.clone()),
                    ..Response::default()
                }));
                let (mut mailbox, _, _, _) =
                    setup_controlled(chip, true, false, 0, response.clone());
                let failure = mailbox.query_encapsulation().unwrap_err();
                assert_eq!(failure.port(), PortState::Usable);
                let eeprom::Failure::Malformed { reply, .. } = failure else {
                    panic!("completed malformed read is not timeout")
                };
                assert!(reply.dma_released);
                assert_eq!(
                    Event::parse(chip, &reply.frame.bytes).unwrap().payload,
                    body
                );
                assert!(!mailbox.is_poisoned());
                assert!(mailbox.last_failure().is_none());
                response.lock().unwrap().encapsulation_payload = Some(eeprom_body(chip, 0xff));
                assert_eq!(
                    mailbox.query_encapsulation().unwrap().observed().byte(),
                    0xff
                );
                // SAFETY: actual modeled requester/firmware/all users stopped.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    fn uncertain_eeprom_exchange_retains_early_response_and_never_reopens_epoch() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for mode in 0..5 {
                let response = Arc::new(Mutex::new(Response {
                    encapsulation_payload: Some(eeprom_body(chip, 0xe3)),
                    unsolicited: mode == 2,
                    drop: mode == 3,
                    ..Response::default()
                }));
                let (mut mailbox, wm, _, _) = setup_controlled(
                    chip,
                    mode != 0,
                    mode == 1,
                    if mode == 4 { usize::MAX } else { 0 },
                    response,
                );
                let failure = mailbox.query_encapsulation_timed(1_000).unwrap_err();
                assert_eq!(failure.port(), PortState::Uncertain);
                assert!(mailbox.is_poisoned());
                assert_eq!(
                    mailbox.last_failure().unwrap().command,
                    Operation::Encapsulation
                );
                if mode == 4 {
                    let reply = mailbox.interrupted_encapsulation_reply().unwrap();
                    assert!(!reply.dma_released);
                    assert_eq!(
                        Event::parse(chip, &reply.frame.bytes).unwrap().payload,
                        eeprom_body(chip, 0xe3)
                    );
                }
                let first = mailbox.last_failure();
                let published = wm.lock().unwrap().completed.len();
                {
                    let mut state = wm.lock().unwrap();
                    state.index = state.head;
                }
                assert!(mailbox.query_encapsulation().is_err());
                assert_eq!(mailbox.last_failure(), first);
                assert_eq!(wm.lock().unwrap().completed.len(), published);
                // SAFETY: actual modeled hardware/firmware/all queue users stopped.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
            }
        }
    }
    #[test]
    #[ignore = "requires exact actual images and full unchanged EEPROM source oracle"]
    fn actual_images_and_eeprom_source_reports_cross_native_dma_with_retained_clc_owner() {
        use super::super::download::Downloader;
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        let oracle = std::path::PathBuf::from(std::env::var("STELA_MT792X_EEPROM_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let response = Arc::new(Mutex::new(Response {
                encapsulation_payload: Some(eeprom_body(chip, 0)),
                require_firmware_start: true,
                ..Response::default()
            }));
            let (mailbox, wm, _, _) = setup_controlled(chip, true, false, 3, response.clone());
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            let auxiliary = prepared.retain_auxiliary();
            let mut downloader = Downloader::new(mailbox);
            assert!(
                downloader
                    .download(&prepared)
                    .unwrap()
                    .firmware_start_acknowledged
            );
            drop(prepared);
            drop(provider);
            let mut mailbox = downloader.into_transport();
            let trace = std::fs::read(oracle.join(alloc::format!("{number}.trace"))).unwrap();
            let mut at = 0;
            for _ in 0..512 {
                let n = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()) as usize;
                at += 2;
                let mut expected_wire = trace[at..at + n].to_vec();
                at += n;
                let n = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()) as usize;
                at += 2;
                let body = &trace[at..at + n];
                at += n;
                let expected_byte = trace[at];
                at += 1;
                response.lock().unwrap().encapsulation_payload = Some(body.to_vec());
                let report = mailbox.query_encapsulation().unwrap();
                assert!(report.belongs_to(&mailbox));
                assert!(report.reply().dma_released);
                assert_eq!(report.observed().raw(), body);
                assert_eq!(report.observed().byte(), expected_byte);
                expected_wire[39] = report.reply().sequence;
                assert_eq!(wm.lock().unwrap().completed.last().unwrap(), &expected_wire);
                let clc = auxiliary.select_clc(report.observed().byte()).unwrap();
                assert_eq!(clc.eeprom_byte(), expected_byte);
                assert_eq!(clc.encapsulation(), report.observed().encapsulation());
                assert!(!auxiliary.release_information().is_empty());
            }
            assert_eq!(at, trace.len());
            // SAFETY: actual modeled firmware/requester/all queue users stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }

    #[test]
    fn native_download_binding_keeps_actual_inputs_and_separate_skipped_patch_outcome() {
        use super::super::download::{PatchState, ReleaseState};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for skipped in [false, true] {
                let response = Arc::new(Mutex::new(Response {
                    patch_already_applied: skipped,
                    ..Response::default()
                }));
                let (mut mailbox, wm, fwdl, _) = setup_controlled(chip, true, false, 3, response);
                let requests = Requests::new(&identity(chip));
                let provider = catalog(&requests, patch_bytes(), ram_bytes());
                let prepared = requests.load(&provider).unwrap();
                let auxiliary = prepared.retain_auxiliary();
                let patch_hash = prepared.patch_image().sha256();
                mailbox.download_with_binding(&prepared).unwrap();
                drop(prepared);
                drop(provider);
                let binding = mailbox.download_binding().unwrap();
                assert_eq!(binding.requests(), &requests);
                assert!(binding.matches_auxiliary(&auxiliary));
                assert_eq!(binding.ram_input().sha256(), auxiliary.sha256());
                assert_eq!(
                    binding.ram_input().provenance().revision,
                    auxiliary.provenance().revision
                );
                assert_eq!(binding.patch_input().sha256(), patch_hash);
                assert_eq!(binding.patch_input().name(), chip.patch_name());
                assert_eq!(binding.patch_input().target().driver, "wifi-mt792x");
                assert_eq!(binding.patch_input().target().hardware, requests.hardware);
                assert_eq!(binding.patch_input().target().board, None);
                let outcome = binding.outcome();
                assert!(outcome.firmware_start_acknowledged);
                assert_eq!(outcome.skipped_ram_regions, 1);
                assert_eq!(
                    outcome.patch,
                    if skipped {
                        PatchState::AlreadyApplied
                    } else {
                        PatchState::Uploaded
                    }
                );
                assert_eq!(
                    outcome.release,
                    if skipped {
                        ReleaseState::NotHeld
                    } else {
                        ReleaseState::Released
                    }
                );
                assert_eq!(
                    fwdl.lock().unwrap().completed.len(),
                    if skipped { 1 } else { 2 }
                );
                assert_eq!(
                    wm.lock().unwrap().completed.len(),
                    if skipped { 3 } else { 6 }
                );
                let mut other_ram = ram_bytes();
                other_ram[0] ^= 1;
                let other_provider = catalog(&requests, patch_bytes(), other_ram);
                let other_aux = requests.load(&other_provider).unwrap().retain_auxiliary();
                assert_eq!(other_aux.requests(), auxiliary.requests());
                assert!(!binding.matches_auxiliary(&other_aux));
                // SAFETY: actual modeled requester/firmware/all users stopped.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
                assert!(mailbox.download_binding().is_none());
            }
        }
    }
    #[test]
    fn failed_native_bound_download_retains_actual_uncertain_owner_without_any_binding() {
        let response = Arc::new(Mutex::new(Response {
            fail_firmware_start_publication: true,
            ..Response::default()
        }));
        let (mut mailbox, wm, fwdl, rx) =
            setup_controlled(Chip::Mt7922, true, false, 0, response.clone());
        let requests = Requests::new(&identity(Chip::Mt7922));
        let provider = catalog(&requests, patch_bytes(), ram_bytes());
        let prepared = requests.load(&provider).unwrap();
        let firmware::Error::Protocol(error) =
            mailbox.download_with_binding(&prepared).unwrap_err()
        else {
            panic!("actual protocol failure")
        };
        assert_eq!(error.stage, super::super::download::Stage::FirmwareStart);
        assert!(response.lock().unwrap().firmware_started);
        assert_eq!(fwdl.lock().unwrap().completed.len(), 2);
        assert!(!error.report.firmware_start_acknowledged);
        assert!(mailbox.download_binding().is_none());
        assert!(mailbox.is_poisoned());
        let count = wm.lock().unwrap().completed.len();
        assert_eq!(
            mailbox.download_with_binding(&prepared).unwrap_err(),
            firmware::Error::NotFresh
        );
        assert_eq!(wm.lock().unwrap().completed.len(), count);
        drop(mailbox);
        for queue in [wm, fwdl, rx] {
            let state = queue.lock().unwrap();
            assert_eq!(state.queue_drops, 0);
            assert!(!state.memory.lock().unwrap().mappings.is_empty());
        }
    }
    #[test]
    fn bound_download_checks_native_identity_before_commands_and_raw_boot_invalidates_success() {
        let chip = Chip::Mt7921;
        let requests = Requests::new(&identity(chip));
        let provider = catalog(&requests, patch_bytes(), ram_bytes());
        let prepared = requests.load(&provider).unwrap();
        let (mut wrong, wm, fwdl, _) = setup(Chip::Mt7922, true, false, 0);
        let firmware::Error::Protocol(error) = wrong.download_with_binding(&prepared).unwrap_err()
        else {
            panic!("actual native target check")
        };
        assert_eq!(error.stage, super::super::download::Stage::FirmwareTarget);
        assert!(wm.lock().unwrap().completed.is_empty());
        assert!(fwdl.lock().unwrap().completed.is_empty());
        assert!(wrong.download_binding().is_none());
        assert!(wrong.is_poisoned());
        // SAFETY: actual modeled requester stopped despite no submitted command.
        unsafe { wrong.release_after_quiesce() }.unwrap();
        let (mut mailbox, _, _, _) = setup(chip, true, false, 0);
        mailbox.download_with_binding(&prepared).unwrap();
        assert!(mailbox.download_binding().is_some());
        mailbox
            .command(Command::PatchSemaphore as u8, &0u32.to_le_bytes())
            .unwrap();
        assert!(mailbox.download_binding().is_none());
        assert_eq!(
            mailbox.download_with_binding(&prepared).unwrap_err(),
            firmware::Error::NotFresh
        );
        assert!(mailbox.download_binding().is_none());
        // SAFETY: actual modeled requester/firmware/all users stopped.
        unsafe { mailbox.release_after_quiesce() }.unwrap();
    }
    #[test]
    #[ignore = "requires exact actual firmware images"]
    fn actual_pinned_downloads_bind_same_owned_clc_input_past_provider_lifetime() {
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let (mut mailbox, _, _, _) = setup(chip, true, false, 3);
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            let auxiliary = prepared.retain_auxiliary();
            mailbox.download_with_binding(&prepared).unwrap();
            drop(prepared);
            drop(provider);
            let binding = mailbox.download_binding().unwrap();
            assert!(binding.matches_auxiliary(&auxiliary));
            assert_eq!(binding.ram_input().name(), chip.ram_name());
            assert!(binding.outcome().firmware_start_acknowledged);
            assert_eq!(binding.ram_input().sha256(), auxiliary.sha256());
            assert!(!auxiliary.release_information().is_empty());
            assert!(auxiliary.select_clc(0).unwrap().region().is_some());
            // SAFETY: actual modeled requester/firmware/all users stopped.
            unsafe { mailbox.release_after_quiesce() }.unwrap();
        }
    }
}
