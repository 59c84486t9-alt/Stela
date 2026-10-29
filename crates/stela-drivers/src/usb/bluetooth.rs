// SPDX-License-Identifier: MIT
//! Physical host USB Bluetooth legacy HCI transport, not an ARM XNU kext.
//!
//! Commands use EP0, events interrupt IN, ACL bulk IN/OUT, without H4 packet
//! indicators. Each transmitted HCI packet is one USB transfer. Receive framing
//! tolerates split/coalesced USB completions, as Linux btusb does. Reference:
//! Bluetooth Core 6.2, Vol 4 Part B sections 2–4 and pinned Linux btusb.c (see
//! bluetooth/THIRD_PARTY.md). No Linux source code is incorporated in this
//! native transport.
//!
//! Attachment opens a **raw transport** and always leaves firmware initialization
//! [`FirmwareStatus::Unverified`]. It does not reset/initialize a controller,
//! load firmware, pair, advertise or provide profiles. The vendor initializers
//! below honor the controller's Num_HCI_Command_Packets credits.
//! The explicit [`intel::initialize`] path adds identified Intel legacy-RSA
//! bootloader bulk framing and returns a controller-specific firmware report.
//! The explicit native [`Hci::initialize_with_provider`] consumer keeps owned
//! device-specific evidence/errors after the provider is released. Raw attachment
//! itself never initializes a controller. [`realtek::initialize`] adds exact
//! RTL8761BU/RTL8822B stock-ROM identification and EPATCH v1 upload with owned
//! observations. Other vendor/format variants remain explicit unsupported paths.
//! [`broadcom::initialize`] adds source-selected Broadcom/Cypress USB PatchRAM
//! identification, complete HCD replay, completion/credit handling and
//! post-download observations. Matching vendor-specific HCI interfaces
//! are admitted separately from the standard class; descriptor IDs never prove
//! the runtime silicon or firmware. A Bluetooth host stack independently
//! establishes radio services. [`qca::initialize`] adds source-listed Rome/WCN
//! USB DFU with OTP/status and exact board-specific rampatch/NVM resources.
//! WCN debug ACL keeps its original bytes as [`Packet::Diagnostic`]; controller
//! dump signatures fail the attachment and keep the first raw fault.
//! A successful USB command submission is not HCI Command Complete/Status.
//! The separate [`mediatek::media`] session adds this PC's initialized MT7925
//! SCO/interrupt-ISO transport. [`realtek::media`] and [`qca::media`] add
//! initialized source profiles' CVSD/queued wideband SCO and bounded delivery
//! receipts. QCA adds explicit acknowledged HCI shutdown. Broader media, physical
//! suspend/resume, hotplug reattachment and guest USB forwarding remain separate.
//!
//! Receive requests remain posted while idle; polling never waits for radio
//! traffic. Incomplete HCI frames have a bounded assembly deadline. Errors close
//! the transport; failed hardware cancellation keeps DMA ownership and prevents
//! reuse. There is no generic method to mark firmware "ready".
pub mod ath3k;
mod binding;
pub mod broadcom;
pub(crate) use crate::bluetooth::hci as command;
mod firmware;
mod host;
mod identity;
mod initialization;
pub mod intel;
pub mod mediatek;
pub mod qca;
pub mod realtek;

pub use binding::{Binding, CLASS};
pub use firmware::FirmwareReceipt;
pub use host::Host;
pub use initialization::{InitializationError, InitializationReport};

use crate::block::BlockError;
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

/// Explicit per-packet transport budget. Larger legal HCI packets are rejected;
/// device-specific buffer sizes/credits still need the Bluetooth host/initializer.
pub const MAX_ACL_PAYLOAD: usize = 4096;
/// bRequest of an HCI command's class request (Bluetooth Core Vol 4 Part B 2.2).
const HCI_COMMAND_REQUEST: u8 = 0;
const EVENT_READ: usize = 512;
const ACL_READ: usize = 8192;
const PARTIAL_US: u64 = 1_000_000;

/// The type of receive endpoint, with separate HCI framing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pipe {
    Event,
    Acl,
}
impl Pipe {
    fn read_bytes(self) -> usize {
        match self {
            Self::Event => EVENT_READ,
            Self::Acl => ACL_READ,
        }
    }
    fn header(self) -> usize {
        match self {
            Self::Event => 2,
            Self::Acl => 4,
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Event => 257,
            Self::Acl => MAX_ACL_PAYLOAD + 4,
        }
    }
}

/// Physical USB boundary, also implemented by stateful transport models.
/// Implementations own their DMA buffers; `receive` returns only completed bytes.
/// `close` must acknowledge cancellation before allowing buffer reuse. If it
/// fails, it must keep/quarantine all possibly hardware-owned buffers forever
/// or until an independently proven controller reset. No method may wait for an
/// unbounded interval. Idle receive polling returns `None` without canceling.
pub trait Io {
    /// Pure kept-owner admission: reject a retired device generation before
    /// accessing MMIO, DMA, completions or changing transport-owned state.
    /// This validates ownership only; it does not attest firmware/radio readiness.
    fn validate(&self) -> Result<(), BlockError>;
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError>;
    /// Completed EP0 IN bytes for identified vendor protocols. Empty means the
    /// device returned a real zero-length transfer, never command completion.
    /// Implementations without that transport fail explicitly.
    fn control_read(&mut self, _setup: [u8; 8]) -> Result<Vec<u8>, BlockError> {
        Err(BlockError::Unsupported(
            "USB Bluetooth control IN transport",
        ))
    }
    fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError>;
    /// Raw bulk OUT; the HCI layer validates ACL or identified vendor commands.
    fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError>;
    /// Identified vendor firmware body on the bound bulk OUT endpoint, with
    /// a per-transfer deadline starting before publication. Cleanup has
    /// its own bounded retirement interval; a timed-out transfer must keep its
    /// owner until acknowledged retirement or permanent quarantine. This is not
    /// an HCI ACL packet. A
    /// transport lacking bounded firmware I/O must refuse rather than silently
    /// substitute an incompatible deadline or framing mode.
    fn write_firmware(&mut self, _bytes: &[u8], _timeout_us: u64) -> Result<(), BlockError> {
        Err(BlockError::Unsupported(
            "bounded Bluetooth firmware bulk output",
        ))
    }
    /// Cancel/acknowledge a posted bulk IN before changing its framing mode.
    fn quiesce_bulk(&mut self) -> Result<(), BlockError>;
    fn close(&mut self) -> Result<(), BlockError>;
    /// `btusb_open` after `btusb_close`: post the receives again. Only a
    /// close that retired every transfer can reopen.
    fn reopen(&mut self) -> Result<(), BlockError> {
        Err(BlockError::Unsupported("USB Bluetooth transport reopen"))
    }
    /// `usb_queue_reset_device`: ask the USB topology owner to reset this
    /// device and bind it again. Every later access through this owner fails.
    fn queue_reset(&mut self) -> Result<(), BlockError> {
        Err(BlockError::Unsupported(
            "USB Bluetooth device reset request",
        ))
    }
    fn now_us(&self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareStatus {
    Unverified,
}

/// Describes USB transport lifecycle only, never Bluetooth firmware/radio state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Usb(BlockError),
    InvalidPacket(&'static str),
    TooLarge {
        maximum: usize,
        actual: usize,
    },
    PartialTimeout(Pipe),
    /// Exact first controller-dump packet. The transport is terminal and its
    /// outstanding DMA must be retired or quarantined; no recovery is implied.
    ControllerDump {
        driver: &'static str,
        packet: Packet,
    },
    Closed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Preserved separately when stopping the failed transport also failed.
    pub cleanup: Option<BlockError>,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "USB Bluetooth {:?}", self.kind)?;
        if let Some(cleanup) = &self.cleanup {
            write!(f, "; cancellation failed: {cleanup}")?;
        }
        Ok(())
    }
}
impl core::error::Error for Error {}
fn error(kind: ErrorKind) -> Error {
    Error {
        kind,
        cleanup: None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Event(Vec<u8>),
    Acl(Vec<u8>),
    /// Original vendor diagnostic frame, including its original ACL header.
    /// This must never be delivered as ordinary Bluetooth ACL data.
    Diagnostic(Vec<u8>),
}

/// Raw legacy HCI transport over a validated USB binding.
pub struct Hci<B: Io> {
    binding: Binding,
    io: B,
    state: State,
    events: Assembler,
    acl: Assembler,
    intel_bootloader: bool,
    initialization: Option<Box<Result<InitializationReport, InitializationError>>>,
}
pub type UsbHci = Hci<Host>;

impl<B: Io> Hci<B> {
    #[cfg(test)]
    pub(crate) fn test_intel_mode(&self) -> bool {
        self.intel_bootloader
    }
    #[cfg(test)]
    pub(crate) fn test_io(&mut self) -> &mut B {
        &mut self.io
    }
    #[cfg(test)]
    pub(crate) fn test_device(&mut self) -> &mut crate::usb::xhci::Device {
        &mut self.binding.device
    }
    /// The binding validates descriptors, not firmware readiness. `io` must
    /// implement the same device/endpoints as the binding, with exclusive use.
    pub fn from_io(binding: Binding, io: B) -> Self {
        Self {
            binding,
            io,
            state: State::Open,
            events: Assembler::new(Pipe::Event),
            acl: Assembler::new(Pipe::Acl),
            intel_bootloader: false,
            initialization: None,
        }
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    /// Last observed lifecycle, not proof that the device is current.
    /// Active operations independently validate the physical owner generation.
    pub fn state(&self) -> State {
        self.state
    }
    pub fn firmware_status(&self) -> FirmwareStatus {
        FirmwareStatus::Unverified
    }

    fn open(&self) -> Result<(), Error> {
        self.io.validate().map_err(|e| error(ErrorKind::Usb(e)))?;
        match self.state {
            State::Open => Ok(()),
            State::Closed => Err(error(ErrorKind::Closed)),
            State::Failed => Err(error(ErrorKind::Failed)),
        }
    }
    fn fail(&mut self, kind: ErrorKind) -> Error {
        self.state = State::Failed;
        Error {
            kind,
            cleanup: self.io.close().err(),
        }
    }

    /// Submit one complete HCI command header+parameters. Success acknowledges
    /// USB delivery only; the initializer/host must await and interpret the HCI
    /// event, enforce command credits and choose its response deadline.
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.open()?;
        if packet.len() < 3 || packet.len() != 3 + usize::from(packet[2]) {
            return Err(error(ErrorKind::InvalidPacket("HCI command length")));
        }
        if self.intel_bootloader && packet[..2] == intel::SECURE_SEND.to_le_bytes() {
            return self
                .io
                .write_acl(packet)
                .map_err(|failure| self.fail(ErrorKind::Usb(failure)));
        }
        // Linux btusb: HCI commands are class requests to the device, wIndex 0.
        let request = super::xhci::setup(
            super::xhci::TYPE_CLASS,
            HCI_COMMAND_REQUEST,
            0,
            0,
            packet.len() as u16,
        );
        self.io
            .control(request, packet)
            .map_err(|failure| self.fail(ErrorKind::Usb(failure)))
    }

    /// One complete HCI ACL header+payload, in one USB transfer. HCI data flow
    /// control and firmware initialization remain the caller's responsibility.
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.open()?;
        if self.intel_bootloader {
            return Err(error(ErrorKind::InvalidPacket(
                "ACL unavailable in Intel bootloader mode",
            )));
        }
        if packet.len() < 4
            || packet.len() != 4 + usize::from(u16::from_le_bytes([packet[2], packet[3]]))
        {
            return Err(error(ErrorKind::InvalidPacket("HCI ACL length")));
        }
        if packet.len() > MAX_ACL_PAYLOAD + 4 {
            return Err(error(ErrorKind::TooLarge {
                maximum: MAX_ACL_PAYLOAD + 4,
                actual: packet.len(),
            }));
        }
        self.io
            .write_acl(packet)
            .map_err(|failure| self.fail(ErrorKind::Usb(failure)))
    }

    /// At most one completed USB chunk per receive pipe; packet framing crosses
    /// polls but never crosses Event/ACL pipes. Empty USB transfers yield no HCI
    /// packet. Malformed frames fail closed and discard this poll's output.
    pub fn poll(&mut self) -> Result<Vec<Packet>, Error> {
        self.open()?;
        let now = self.io.now_us();
        for (pipe, since) in [
            (Pipe::Event, self.events.since),
            (Pipe::Acl, self.acl.since),
        ] {
            if since.is_some_and(|since| now.saturating_sub(since) >= PARTIAL_US) {
                return Err(self.fail(ErrorKind::PartialTimeout(pipe)));
            }
        }
        let mut packets = Vec::new();
        for pipe in [Pipe::Event, Pipe::Acl] {
            let bytes = match self.io.receive(pipe) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => continue,
                Err(failure) => return Err(self.fail(ErrorKind::Usb(failure))),
            };
            if bytes.len() > pipe.read_bytes() {
                return Err(self.fail(ErrorKind::TooLarge {
                    maximum: pipe.read_bytes(),
                    actual: bytes.len(),
                }));
            }
            let assembler = match pipe {
                Pipe::Event => &mut self.events,
                Pipe::Acl => &mut self.acl,
            };
            let frames = match assembler.feed(&bytes, now) {
                Ok(frames) => frames,
                Err(failure) => return Err(self.fail(failure)),
            };
            for frame in frames {
                let packet = match pipe {
                    Pipe::Event => Packet::Event(frame),
                    Pipe::Acl if self.intel_bootloader => Packet::Event(frame),
                    Pipe::Acl => Packet::Acl(frame),
                };
                let Some(packet) = mediatek::packet::classify(self.binding.device(), packet) else {
                    continue;
                };
                match qca::classify(self.binding.device(), packet) {
                    Ok(packet) => packets.push(packet),
                    Err(packet) => {
                        return Err(self.fail(ErrorKind::ControllerDump {
                            driver: "qualcomm-usb",
                            packet,
                        }));
                    }
                }
            }
        }
        Ok(packets)
    }

    // Private to this module and its identified vendor initializer. Both pipes
    // must have complete frames; cancel the posted bulk TD before reframing it.
    fn intel_mode(&mut self, bootloader: bool) -> Result<(), Error> {
        self.open()?;
        if self.events.since.is_some() || self.acl.since.is_some() {
            return Err(self.fail(ErrorKind::InvalidPacket(
                "partial HCI frame at mode transition",
            )));
        }
        self.io
            .quiesce_bulk()
            .map_err(|failure| self.fail(ErrorKind::Usb(failure)))?;
        self.acl = Assembler::new(if bootloader { Pipe::Event } else { Pipe::Acl });
        self.intel_bootloader = bootloader;
        Ok(())
    }

    /// Open a cleanly closed transport again with empty assemblers, as power-on
    /// does after power-off. A failed close stays terminal.
    pub(in crate::usb::bluetooth) fn reopen(&mut self) -> Result<(), Error> {
        self.io.validate().map_err(|e| error(ErrorKind::Usb(e)))?;
        match self.state {
            State::Closed => {}
            State::Failed => return Err(error(ErrorKind::Failed)),
            State::Open => {
                return Err(error(ErrorKind::Usb(BlockError::Unsupported(
                    "USB Bluetooth transport is open",
                ))));
            }
        }
        if let Err(e) = self.io.reopen() {
            self.state = State::Failed;
            return Err(error(ErrorKind::Usb(e)));
        }
        self.events = Assembler::new(Pipe::Event);
        self.acl = Assembler::new(Pipe::Acl);
        self.state = State::Open;
        Ok(())
    }

    /// Stop outstanding USB receives. Idempotent success still requires the same
    /// live device generation; a failed close is terminal and cannot be used as
    /// a reopen/reset shortcut.
    pub fn close(&mut self) -> Result<(), Error> {
        self.io.validate().map_err(|e| error(ErrorKind::Usb(e)))?;
        if self.state == State::Closed {
            return Ok(());
        }
        self.open()?;
        match self.io.close() {
            Ok(()) => {
                self.state = State::Closed;
                Ok(())
            }
            Err(failure) => {
                self.state = State::Failed;
                Err(error(ErrorKind::Usb(failure)))
            }
        }
    }
}

impl<B: Io> Hci<B> {
    /// `usb_queue_reset_device`: close this transport, then ask the USB
    /// topology owner to reset the device and bind a fresh transport, even
    /// when the close failed.
    pub fn queue_reset(&mut self) -> Result<(), Error> {
        let closed = if self.state == State::Open {
            self.close()
        } else {
            Ok(())
        };
        self.io
            .queue_reset()
            .map_err(|e| error(ErrorKind::Usb(e)))?;
        closed
    }
}

impl<B: Io> Drop for Hci<B> {
    fn drop(&mut self) {
        // Call close explicitly to observe quiescence errors. Drop is best-effort;
        // the backend must quarantine DMA when cancellation cannot be acknowledged.
        if self.state == State::Open {
            self.state = if self.io.close().is_ok() {
                State::Closed
            } else {
                State::Failed
            };
        }
    }
}

struct Assembler {
    pipe: Pipe,
    bytes: Vec<u8>,
    expected: usize,
    since: Option<u64>,
}
impl Assembler {
    fn new(pipe: Pipe) -> Self {
        Self {
            pipe,
            bytes: Vec::new(),
            expected: pipe.header(),
            since: None,
        }
    }
    fn feed(&mut self, mut input: &[u8], now: u64) -> Result<Vec<Vec<u8>>, ErrorKind> {
        let mut frames = Vec::new();
        while !input.is_empty() {
            if self.bytes.is_empty() {
                self.since = Some(now);
            }
            let take = (self.expected - self.bytes.len()).min(input.len());
            self.bytes.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.bytes.len() < self.expected {
                continue;
            }
            if self.expected == self.pipe.header() {
                let payload = match self.pipe {
                    Pipe::Event => usize::from(self.bytes[1]),
                    Pipe::Acl => usize::from(u16::from_le_bytes([self.bytes[2], self.bytes[3]])),
                };
                self.expected += payload;
                if self.expected > self.pipe.maximum() {
                    return Err(ErrorKind::TooLarge {
                        maximum: self.pipe.maximum(),
                        actual: self.expected,
                    });
                }
                if self.bytes.len() < self.expected {
                    continue;
                }
            }
            if self.pipe == Pipe::Event {
                let event = &self.bytes;
                if event[0] == 0
                    || (event[0] == 0x0e && event[1] < 3)
                    || (event[0] == 0x0f && event[1] != 4)
                {
                    return Err(ErrorKind::InvalidPacket("HCI event header/parameters"));
                }
            }
            frames.push(core::mem::take(&mut self.bytes));
            self.expected = self.pipe.header();
            self.since = None;
        }
        Ok(frames)
    }
}

#[cfg(test)]
pub(crate) use host::tests::generation as generation_tests;

#[cfg(test)]
mod tests;
