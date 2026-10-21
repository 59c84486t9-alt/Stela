// SPDX-License-Identifier: MIT
//! Physical host USB Bluetooth legacy HCI transport, not an ARM XNU kext.
//!
//! Commands use EP0, events interrupt IN, ACL bulk IN/OUT, without H4 packet
//! indicators. Each transmitted HCI packet is one USB transfer. Receive framing
//! tolerates split/coalesced USB completions, as Linux btusb does. Reference:
//! Bluetooth Core 6.2, Vol 4 Part B sections 2–4 and pinned Linux btusb.c (see
//! THIRD_PARTY.md). No Linux source code is incorporated in this native transport.
//!
//! Attachment opens a **raw transport** and always leaves firmware initialization
//! [`FirmwareStatus::Unverified`]. It does not reset/initialize a controller,
//! load firmware, pair, advertise, manage HCI credits or provide profiles.
//! The explicit [`intel::initialize`] path adds identified Intel legacy-RSA
//! bootloader bulk framing and returns a controller-specific firmware report.
//! The explicit native [`Hci::initialize_with_provider`] consumer retains owned
//! device-specific evidence/errors after the provider is released. Raw attachment
//! itself never initializes a controller. Other vendor initialization remains unsupported. A Bluetooth host stack must
//! independently establish radio services after controller initialization.
//! A successful USB command submission is not HCI Command Complete/Status.
//! SCO, USB isochronous/ISO traffic, bulk serialization, hotplug reattachment,
//! suspend/resume and guest USB forwarding remain unsupported/separate work.
//!
//! Receive requests remain posted while idle; polling never waits for radio
//! traffic. Incomplete HCI frames have a bounded assembly deadline. Errors close
//! the transport; failed hardware cancellation retains DMA ownership and prevents
//! reuse. There is deliberately no generic method to mark firmware "ready".
mod binding;
mod host;
mod initialization;
pub mod intel;

pub use binding::{Binding, CLASS};
pub use host::Host;
pub use initialization::{InitializationError, InitializationReport};

use crate::block::BlockError;
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

/// Explicit per-packet transport budget. Larger legal HCI packets are rejected;
/// device-specific buffer sizes/credits still need the Bluetooth host/initializer.
pub const MAX_ACL_PAYLOAD: usize = 4096;
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
        let index = if self.binding.recipient == 0x21 {
            u16::from(self.binding.interface)
        } else {
            0
        };
        let request = super::xhci::setup(self.binding.recipient, 0, 0, index, packet.len() as u16);
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
    use alloc::{collections::VecDeque, rc::Rc};
    use core::cell::Cell;

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
        for composite in [false, true] {
            let mut hci = Hci::from_io(binding(composite), Model::default());
            let packet = [3, 0x0c, 0]; // Reset, submitted without fabricating its response.
            hci.submit_command(&packet).unwrap();
            assert_eq!(
                hci.io.control,
                vec![(
                    [
                        if composite { 0x21 } else { 0x20 },
                        0,
                        0,
                        0,
                        if composite { 2 } else { 0 },
                        0,
                        3,
                        0
                    ],
                    packet.to_vec()
                )]
            );
            assert!(hci.poll().unwrap().is_empty());
            assert_eq!(hci.state(), State::Open);
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            assert_eq!(
                hci.binding().device().configuration,
                device(composite).configuration
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
    fn descriptors_must_be_complete_unambiguous_and_compatible() {
        let original = device(false);
        let rejects = |d: &Device| {
            xhci::interfaces(&d.configuration)
                .first()
                .is_none_or(|interface| Binding::new(d, interface).is_err())
        };
        for index in [0, 1, 2, 4, 5, 9, 13, 18, 20, 22, 24, 25] {
            let mut d = original.clone();
            d.configuration[index] = 0;
            assert!(rejects(&d), "configuration byte {index}");
        }
        let mut d = original.clone();
        d.configuration.pop();
        assert!(rejects(&d));
        let mut d = original.clone();
        d.configuration[20] = 0x82;
        assert!(rejects(&d)); // duplicate role/address
        let mut d = original.clone();
        d.configuration[21] = 1;
        assert!(rejects(&d)); // isochronous
        let mut d = original.clone();
        d.speed = xhci::SUPER_SPEED;
        assert!(rejects(&d));
        let mut fabricated = xhci::interfaces(&original.configuration)[0].clone();
        fabricated.number = 4;
        assert!(Binding::new(&original, &fabricated).is_err());
        let sco = &xhci::interfaces(&original.configuration)[1];
        assert!(Binding::new(&original, sco).unwrap_err().contains("SCO"));
    }

    #[test]
    fn iad_composite_context_selects_interface_and_requires_matching_function() {
        let mut d = device(true);
        d.descriptor[4..7].copy_from_slice(&[0xef, 2, 1]);
        assert!(Binding::new(&d, &xhci::interfaces(&d.configuration)[2]).is_err());
        d.configuration.splice(27..27, [8, 11, 2, 2, 0xe0, 1, 1, 0]);
        let length = d.configuration.len() as u16;
        d.configuration[2..4].copy_from_slice(&length.to_le_bytes());
        let selected = Binding::new(&d, &xhci::interfaces(&d.configuration)[2]).unwrap();
        assert_eq!(selected.recipient, 0x21);
        assert_eq!(selected.interface(), 2);
    }

    #[test]
    fn single_function_nonzero_interface_keeps_device_recipient_and_discovers_endpoints() {
        let mut device = device(false);
        device.configuration[11] = 1;
        device.configuration[41] = 2;
        device.configuration[20] = 0x87;
        device.configuration[27] = 0x86;
        device.configuration[34] = 0x06;
        device
            .configuration
            .splice(9..9, [9, 4, 0, 0, 0, 0xff, 0, 0, 0]);
        device.configuration[4] = 3;
        let length = device.configuration.len() as u16;
        device.configuration[2..4].copy_from_slice(&length.to_le_bytes());
        let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[1]).unwrap();
        assert_eq!(binding.interface(), 1);
        assert_eq!(binding.events.address, 0x87);
        assert_eq!(binding.input.address, 0x86);
        assert_eq!(binding.output.address, 0x06);
        let mut hci = Hci::from_io(binding, Model::default());
        hci.submit_command(&[3, 0x0c, 0]).unwrap();
        assert_eq!(hci.io.control[0].0, [0x20, 0, 0, 0, 0, 0, 3, 0]);
    }
}
