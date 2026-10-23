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
//! The explicit native [`Hci::initialize_with_provider`] consumer retains owned
//! device-specific evidence/errors after the provider is released. Raw attachment
//! itself never initializes a controller. [`realtek::initialize`] adds exact
//! RTL8761BU/RTL8822B stock-ROM identification and EPATCH v1 upload with owned
//! observations. Other vendor/format variants remain explicit unsupported paths.
//! [`broadcom::initialize`] adds source-selected Broadcom/Cypress USB PatchRAM
//! identification, complete HCD replay, genuine completion/credit handling and
//! retained post-download observations. Matching vendor-specific HCI interfaces
//! are admitted separately from the standard class; descriptor IDs never prove
//! the runtime silicon or firmware. A Bluetooth host stack independently
//! establishes radio services.
//! A successful USB command submission is not HCI Command Complete/Status.
//! The separate [`mediatek::media`] session adds this PC's initialized MT7925
//! SCO/interrupt-ISO transport. Generic media, bulk serialization, physical
//! suspend/resume, hotplug reattachment and guest USB forwarding remain separate.
//!
//! Receive requests remain posted while idle; polling never waits for radio
//! traffic. Incomplete HCI frames have a bounded assembly deadline. Errors close
//! the transport; failed hardware cancellation retains DMA ownership and prevents
//! reuse. There is deliberately no generic method to mark firmware "ready".
mod binding;
pub mod broadcom;
mod command;
mod firmware;
mod host;
mod initialization;
pub mod intel;
pub mod mediatek;
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
/// fails, it must retain/quarantine all possibly hardware-owned buffers forever
/// or until an independently proven controller reset. No method may wait for an
/// unbounded interval. Idle receive polling returns `None` without canceling.
pub trait Io {
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
    /// Cancel/acknowledge a posted bulk IN before changing its framing mode.
    fn quiesce_bulk(&mut self) -> Result<(), BlockError>;
    fn close(&mut self) -> Result<(), BlockError>;
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
    TooLarge { maximum: usize, actual: usize },
    PartialTimeout(Pipe),
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
    pub fn state(&self) -> State {
        self.state
    }
    pub fn firmware_status(&self) -> FirmwareStatus {
        FirmwareStatus::Unverified
    }

    fn open(&self) -> Result<(), Error> {
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
            packets.extend(frames.into_iter().map(|frame| match pipe {
                Pipe::Event => Packet::Event(frame),
                Pipe::Acl if self.intel_bootloader => Packet::Event(frame),
                Pipe::Acl => Packet::Acl(frame),
            }));
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

    /// Stop outstanding USB receives. This is idempotent after successful close;
    /// a failed close is terminal and cannot be used as a reopen/reset shortcut.
    pub fn close(&mut self) -> Result<(), Error> {
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
mod tests {
    use super::*;
    use crate::usb::xhci::{self, Device};
    use crate::usb::xhci::{model::*, *};
    use alloc::{collections::VecDeque, rc::Rc};
    use core::cell::Cell;
    use core::cell::RefCell;

    fn device(composite: bool) -> Device {
        let first = if composite { 2 } else { 0 };
        let mut configuration = vec![
            9,
            2,
            48,
            0,
            2,
            1,
            0,
            0x80,
            50,
            9,
            4,
            first,
            0,
            3,
            0xe0,
            1,
            1,
            0,
            7,
            5,
            0x81,
            3,
            16,
            0,
            1,
            7,
            5,
            0x82,
            2,
            64,
            0,
            0,
            7,
            5,
            0x02,
            2,
            64,
            0,
            0,
            9,
            4,
            first + 1,
            0,
            0,
            0xe0,
            1,
            1,
            0,
        ];
        if composite {
            configuration.splice(
                9..9,
                [9, 4, 0, 0, 0, 0xff, 0, 0, 0, 9, 4, 1, 0, 0, 0xff, 0, 0, 0],
            );
            configuration[4] = 4;
        }
        let length = configuration.len() as u16;
        configuration[2..4].copy_from_slice(&length.to_le_bytes());
        Device {
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
            slot: 1,
            speed: xhci::FULL_SPEED,
            location: "model USB".into(),
            descriptor: [
                18,
                1,
                0,
                2,
                if composite { 0 } else { 0xe0 },
                if composite { 0 } else { 1 },
                if composite { 0 } else { 1 },
                64,
                0x34,
                0x12,
                0x78,
                0x56,
                0,
                1,
                0,
                0,
                0,
                1,
            ],
            configurations: vec![configuration.clone()],
            configuration,
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
        }
    }
    fn binding(composite: bool) -> Binding {
        let device = device(composite);
        let interfaces = xhci::interfaces(&device.configuration);
        Binding::new(
            &device,
            interfaces
                .iter()
                .find(|interface| interface.endpoints.len() == 3)
                .unwrap(),
        )
        .unwrap()
    }

    #[derive(Default)]
    struct Model {
        control: Vec<([u8; 8], Vec<u8>)>,
        sent: Vec<Vec<u8>>,
        events: VecDeque<Result<Vec<u8>, BlockError>>,
        acl: VecDeque<Result<Vec<u8>, BlockError>>,
        clock: u64,
        close_count: Rc<Cell<usize>>,
        close_error: Option<BlockError>,
        control_error: Option<BlockError>,
        write_error: Option<BlockError>,
        receive_count: usize,
    }
    impl Io for Model {
        fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
            self.control.push((setup, packet.to_vec()));
            match self.control_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError> {
            self.receive_count += 1;
            match pipe {
                Pipe::Event => &mut self.events,
                Pipe::Acl => &mut self.acl,
            }
            .pop_front()
            .transpose()
        }
        fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError> {
            self.sent.push(packet.to_vec());
            match self.write_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), BlockError> {
            self.close_count.set(self.close_count.get() + 1);
            match self.close_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        fn now_us(&self) -> u64 {
            self.clock
        }
    }

    #[test]
    fn class_requests_use_device_context_not_sco_interface_count() {
        {
            let mut hci = Hci::from_io(binding(false), Model::default());
            let packet = [3, 0x0c, 0]; // Reset, submitted without fabricating its response.
            hci.submit_command(&packet).unwrap();
            assert_eq!(
                hci.io.control,
                vec![([0x20, 0, 0, 0, 0, 0, 3, 0], packet.to_vec())]
            );
            assert!(hci.poll().unwrap().is_empty());
            assert_eq!(hci.state(), State::Open);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            assert_eq!(
                hci.binding().device().configuration,
                device(false).configuration
            );
        }
    }

    #[test]
    fn transmit_validates_full_hci_packets_without_h4_prefix_or_fragmentation() {
        let mut hci = Hci::from_io(binding(false), Model::default());
        for packet in [&[][..], &[3, 0x0c], &[3, 0x0c, 1], &[3, 0x0c, 0, 99]] {
            assert!(matches!(
                hci.submit_command(packet).unwrap_err().kind,
                ErrorKind::InvalidPacket(_)
            ));
        }
        for packet in [&[][..], &[1, 0, 0], &[1, 0, 1, 0], &[1, 0, 0, 0, 9]] {
            assert!(matches!(
                hci.submit_acl(packet).unwrap_err().kind,
                ErrorKind::InvalidPacket(_)
            ));
        }
        let mut oversized = vec![0; MAX_ACL_PAYLOAD + 5];
        oversized[2..4].copy_from_slice(&((MAX_ACL_PAYLOAD + 1) as u16).to_le_bytes());
        assert!(matches!(
            hci.submit_acl(&oversized).unwrap_err().kind,
            ErrorKind::TooLarge { .. }
        ));
        assert!(hci.io.control.is_empty());
        assert!(hci.io.sent.is_empty());
        let acl = [1, 0x20, 3, 0, 0xaa, 0xbb, 0xcc];
        hci.submit_acl(&acl).unwrap();
        assert_eq!(hci.io.sent, vec![acl.to_vec()]);
        assert_eq!(hci.state(), State::Open);
    }

    #[test]
    fn every_header_payload_split_and_coalesced_packet_is_reassembled_per_pipe() {
        let event = [0x0e, 4, 1, 3, 0x0c, 0];
        let acl = [1, 0x20, 3, 0, 9, 8, 7];
        for event_split in 1..event.len() {
            for acl_split in 1..acl.len() {
                let mut model = Model::default();
                model.events.push_back(Ok(event[..event_split].to_vec()));
                let mut events = event[event_split..].to_vec();
                events.extend([0xff, 0]);
                model.events.push_back(Ok(events));
                model.acl.push_back(Ok(acl[..acl_split].to_vec()));
                let mut acls = acl[acl_split..].to_vec();
                acls.extend([2, 0, 0, 0]);
                model.acl.push_back(Ok(acls));
                let mut hci = Hci::from_io(binding(false), model);
                assert!(hci.poll().unwrap().is_empty());
                assert_eq!(
                    hci.poll().unwrap(),
                    vec![
                        Packet::Event(event.to_vec()),
                        Packet::Event(vec![0xff, 0]),
                        Packet::Acl(acl.to_vec()),
                        Packet::Acl(vec![2, 0, 0, 0])
                    ]
                );
            }
        }
    }

    #[test]
    fn partial_packet_has_a_fixed_deadline_and_idle_endpoints_do_not() {
        let mut model = Model::default();
        model.events.push_back(Ok(vec![0x0e]));
        let mut hci = Hci::from_io(binding(false), model);
        assert!(hci.poll().unwrap().is_empty());
        hci.io.clock = PARTIAL_US - 1;
        hci.io.events.push_back(Ok(vec![4])); // Progress must not extend the deadline.
        assert!(hci.poll().unwrap().is_empty());
        hci.io.clock = PARTIAL_US;
        assert_eq!(
            hci.poll().unwrap_err().kind,
            ErrorKind::PartialTimeout(Pipe::Event)
        );
        assert_eq!(hci.io.close_count.get(), 1);
        let mut idle = Hci::from_io(binding(false), Model::default());
        idle.io.clock = u64::MAX;
        assert!(idle.poll().unwrap().is_empty());
        assert_eq!(idle.state(), State::Open);
    }

    #[test]
    fn malformed_events_and_acl_lengths_close_without_partial_delivery() {
        for bytes in [vec![0, 0], vec![0x0e, 2, 1, 3], vec![0x0f, 3, 0, 1, 3]] {
            let mut model = Model::default();
            model.events.push_back(Ok(bytes));
            let mut hci = Hci::from_io(binding(false), model);
            assert!(matches!(
                hci.poll().unwrap_err().kind,
                ErrorKind::InvalidPacket(_)
            ));
            assert_eq!(hci.state(), State::Failed);
            assert_eq!(hci.io.close_count.get(), 1);
        }
        let mut model = Model::default();
        model.acl.push_back(Ok(vec![1, 0, 1, 0x10]));
        let mut hci = Hci::from_io(binding(false), model);
        assert_eq!(
            hci.poll().unwrap_err().kind,
            ErrorKind::TooLarge {
                maximum: MAX_ACL_PAYLOAD + 4,
                actual: MAX_ACL_PAYLOAD + 5
            }
        );
    }

    #[test]
    fn endpoint_stall_disconnect_and_cleanup_failure_are_terminal() {
        for failure in [
            BlockError::Device {
                status: xhci::STALL,
            },
            BlockError::Unsupported("USB Bluetooth device disconnected"),
            BlockError::Timeout,
        ] {
            let mut model = Model::default();
            model.events.push_back(Err(failure.clone()));
            model.close_error = Some(BlockError::Timeout);
            let mut hci = Hci::from_io(binding(false), model);
            let error = hci.poll().unwrap_err();
            assert_eq!(error.kind, ErrorKind::Usb(failure));
            assert_eq!(error.cleanup, Some(BlockError::Timeout));
            let receives = hci.io.receive_count;
            assert_eq!(hci.poll().unwrap_err().kind, ErrorKind::Failed);
            assert_eq!(
                hci.submit_command(&[3, 0x0c, 0]).unwrap_err().kind,
                ErrorKind::Failed
            );
            assert_eq!(hci.io.receive_count, receives);
            assert_eq!(hci.io.close_count.get(), 1);
        }
    }

    #[test]
    fn command_and_acl_usb_failures_never_report_success() {
        let mut model = Model {
            control_error: Some(BlockError::Timeout),
            ..Model::default()
        };
        let mut hci = Hci::from_io(binding(false), model);
        assert_eq!(
            hci.submit_command(&[3, 0x0c, 0]).unwrap_err().kind,
            ErrorKind::Usb(BlockError::Timeout)
        );
        assert_eq!(hci.io.close_count.get(), 1);
        model = Model {
            write_error: Some(BlockError::Device { status: 4 }),
            ..Model::default()
        };
        let mut hci = Hci::from_io(binding(false), model);
        assert_eq!(
            hci.submit_acl(&[1, 0, 0, 0]).unwrap_err().kind,
            ErrorKind::Usb(BlockError::Device { status: 4 })
        );
    }

    #[test]
    fn explicit_close_and_drop_cancel_without_reopening() {
        let count = Rc::new(Cell::new(0));
        {
            let model = Model {
                close_count: count.clone(),
                ..Model::default()
            };
            let mut hci = Hci::from_io(binding(false), model);
            hci.close().unwrap();
            hci.close().unwrap();
            assert_eq!(hci.state(), State::Closed);
            assert_eq!(hci.poll().unwrap_err().kind, ErrorKind::Closed);
        }
        assert_eq!(count.get(), 1);
        {
            let model = Model {
                close_count: count.clone(),
                ..Model::default()
            };
            let _hci = Hci::from_io(binding(false), model);
        }
        assert_eq!(count.get(), 2);
    }

    #[test]
    fn hci_interfaces_need_their_three_endpoints_on_interface_zero() {
        let original = device(false);
        let first = |d: &Device| xhci::interfaces(&d.configuration)[0].clone();
        assert!(Binding::new(&original, &first(&original)).is_ok());
        // Without its bulk IN endpoint (made a second interrupt IN) the
        // interface has no inbound ACL pipe.
        let mut d = original.clone();
        d.configuration[28] = 3;
        assert_eq!(
            Binding::new(&d, &first(&d)).unwrap_err(),
            "Bluetooth HCI endpoints are missing"
        );
        let mut d = original.clone();
        d.speed = xhci::SUPER_SPEED;
        assert!(Binding::new(&d, &first(&d)).is_err());
        let mut fabricated = first(&original);
        fabricated.number = 4;
        assert!(Binding::new(&original, &fabricated).is_err());
        let sco = &xhci::interfaces(&original.configuration)[1];
        assert!(Binding::new(&original, sco).is_err());
    }

    #[test]
    fn extra_endpoints_are_ignored_and_other_interfaces_refused_like_btusb() {
        let mut d = device(true);
        d.descriptor[4..7].copy_from_slice(&[0xef, 2, 1]);
        assert_eq!(
            Binding::new(&d, &xhci::interfaces(&d.configuration)[2]).unwrap_err(),
            "Bluetooth HCI on an interface other than 0"
        );
    }

    #[test]
    fn hci_interface_discovers_its_endpoints_and_commands_go_to_the_device() {
        let mut device = device(false);
        device.configuration[41] = 2;
        device.configuration[20] = 0x87;
        device.configuration[27] = 0x86;
        device.configuration[34] = 0x06;
        device
            .configuration
            .splice(9..9, [9, 4, 1, 0, 0, 0xff, 0, 0, 0]);
        device.configuration[4] = 3;
        let length = device.configuration.len() as u16;
        device.configuration[2..4].copy_from_slice(&length.to_le_bytes());
        let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[1]).unwrap();
        assert_eq!(binding.interface(), 0);
        assert_eq!(binding.events.address, 0x87);
        assert_eq!(binding.input.address, 0x86);
        assert_eq!(binding.output.address, 0x06);
        let mut hci = Hci::from_io(binding, Model::default());
        hci.submit_command(&[3, 0x0c, 0]).unwrap();
        assert_eq!(hci.io.control[0].0, [0x20, 0, 0, 0, 0, 0, 3, 0]);
    }

    #[test]
    fn bluetooth_binds_real_xhci_queues_moves_packets_and_stops_on_disconnect() {
        use crate::usb::bluetooth::{FirmwareStatus, Packet, State};
        for scenario in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: this boot-lifetime-style allocation outlives every model DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            let shared: Shared = Rc::new(RefCell::new(controller));
            let mut device = Device {
                vendor_ethernet_revision: None,
                vendor_ethernet_tcr: None,
                slot: 1,
                speed: FULL_SPEED,
                location: "modeled physical HCI".into(),
                descriptor: [
                    18, 1, 0, 2, 0xe0, 1, 1, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
                ],
                configurations: Vec::new(),
                configuration: vec![
                    9, 2, 48, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3,
                    16, 0, 1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0, 9, 4, 1, 0, 0,
                    0xe0, 1, 1, 0,
                ],
                manufacturer: None,
                product: None,
                serial: None,
                language: None,
            };
            device.configurations = vec![device.configuration.clone()];
            let mut found = Found::default();
            bind(&shared, device, &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.bluetooth.len(), 1);
            if scenario == 0 {
                let count = model.borrow().seen.len();
                drop(found);
                assert_eq!(model.borrow().seen.len(), count);
                continue;
            }
            let mut hci = found.bluetooth.pop().unwrap();
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            hci.submit_command(&[3, 0x0c, 0]).unwrap();
            assert_eq!(
                model.borrow().setup.last().unwrap(),
                &([0x20, 0, 0, 0, 0, 0, 3, 0], vec![3, 0x0c, 0])
            );
            assert!(hci.poll().unwrap().is_empty());
            model
                .borrow_mut()
                .incoming_events
                .push_back(vec![0x0e, 4, 1, 3, 0x0c, 0]);
            model
                .borrow_mut()
                .incoming_acl
                .push_back(vec![1, 0x20, 2, 0, 0xab, 0xcd]);
            assert_eq!(
                hci.poll().unwrap(),
                vec![
                    Packet::Event(vec![0x0e, 4, 1, 3, 0x0c, 0]),
                    Packet::Acl(vec![1, 0x20, 2, 0, 0xab, 0xcd])
                ]
            );
            hci.submit_acl(&[2, 0x20, 1, 0, 0x42]).unwrap();
            assert_eq!(model.borrow().outgoing, vec![vec![2, 0x20, 1, 0, 0x42]]);
            assert!(hci.poll().unwrap().is_empty()); // Leaves both IN TDs active.
            model.borrow_mut().connected = false;
            if scenario == 2 {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
            }
            let error = hci.poll().unwrap_err();
            assert_eq!(hci.state(), State::Failed);
            if scenario == 1 {
                assert_eq!(error.cleanup, None);
                assert_eq!(model.borrow().state(3), 3);
                assert_eq!(model.borrow().state(5), 3);
                assert!(model.borrow().active[3].is_none());
                assert!(model.borrow().active[5].is_none());
            } else {
                assert_eq!(error.cleanup, Some(BlockError::Device { status: 11 }));
                for dci in [3, 5] {
                    assert_eq!(model.borrow().state(dci), 1);
                    assert!(model.borrow().active[dci].is_some());
                    assert!(shared.borrow().endpoint_poisoned(1, dci));
                }
                assert!(hci.poll().is_err());
            }
            let count = model.borrow().seen.len();
            drop(hci);
            assert_eq!(model.borrow().seen.len(), count); // Drop does not reset another device.
        }
    }
}
