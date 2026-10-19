//! The emulated sepOS active phase. Stela is the SEP, with its own keys.
//!
//! Once SEPROM accepts the delivered container under Stela's trust policy
//! (see [`super::firmware`]), this phase speaks the AP-facing boot-completion
//! protocol. `AppleSEPBooter::bootSEP` 0x2d73ddc..0x2d73e68 maps the aggregate
//! shared-memory buffer and sends its slave address and size on service 0xfe;
//! the SEP then notifies the control endpoint that the OS is active. That
//! notification drives `AppleSEPManager::notifyOSActive` 0x2d6c998 and
//! `_notifyOSActiveGated` 0x2d6b38c, which publishes `sepBootedOnce`
//! (0x2d6b558) and advances the manager to its booted state.
//!
//! The control endpoint ([`super::control`]) then answers the AP's tagged
//! requests and consumes its notifications.
//!
//! Right after OS active the SEP advertises its catalog of implemented
//! application services on discovery (0xfd), each name record before its
//! capacity record. `AppleSEPDiscovery::_msgReceived` 0x2d64a00 only asserts
//! that it runs on the manager's work loop; it accepts records in any manager
//! state and `_exposeNub` 0x2d64db4 publishes the nub at once. The state-8
//! gate (`AppleSEPManager::_waitUntilCanSendMessage` 0x2d6bcc4..0x2d6bd30,
//! passed once `_notifyOSActiveGated` advances the manager) holds back only
//! the AP's own sends, such as a client's OOL registration; SEP-sent traffic
//! is not gated. Only services with a native implementation are cataloged:
//! a guessed advertisement would make the kernel create a nub it then blocks
//! on. docs/research/sep.md owns the recovered contract.
//!
//! Application-service frames wait for the SEP's DMA step, where the service
//! reads its request from, and writes its result to, the OOL buffers its AP
//! client registered; the reply follows only once that has succeeded.
use super::super::asc::Message;
use super::{
    Entropy, SecurityMode,
    control::{self, Request, Status},
    endpoint::Catalog,
    message::{self, Frame},
    ool::Buffers,
    shared::Region,
    store::{Backend, Nonces},
    xart::{self, Payload, Xart},
};
use crate::platform::dma::{DmaError, Port};
use alloc::{boxed::Box, vec::Vec};

/// The SEP's power state as the control endpoint drives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Awake,
    /// `cmsgSLEEP`'s sleep type, until `cmsgWAKE`.
    Asleep(u8),
    /// After the AP's `cmsgNAP`, until its nap wake word.
    Napping,
}

pub struct SepOs {
    region: Option<Region>,
    os_active_sent: bool,
    security: Option<SecurityMode>,
    power: Power,
    ap_sleep_ready: bool,
    buffers: Vec<Buffers>,
    catalog: Catalog,
    xart: Option<Xart>,
    /// Application-service requests awaiting the DMA step, in arrival order.
    pending: Vec<Frame>,
}

/// The SEP page that scales discovery capacities: 16 KiB, since
/// `AppleSEPManager::start` 0x2d67308 selects it from the SEP node's `aarch64`
/// property, which `soc::sep_device` requires.
pub const SEP_PAGE_BYTES: u32 = 0x4000;

impl SepOs {
    pub fn new(security: Option<SecurityMode>) -> Self {
        Self {
            region: None,
            os_active_sent: false,
            security,
            power: Power::Awake,
            ap_sleep_ready: false,
            buffers: Vec::new(),
            catalog: Catalog::empty(),
            xart: None,
            pending: Vec::new(),
        }
    }

    /// The SEP's native services: the xART pair, advertised once OS active
    /// is reported, over the anti-replay store `store`.
    pub fn with_services(mut self, store: Nonces<Box<dyn Backend>>) -> Result<Self, &'static str> {
        self.catalog = Catalog::new(xart::services().to_vec())?;
        self.xart = Some(Xart::new(store));
        Ok(self)
    }

    /// The xART service state, when installed.
    pub fn xart(&self) -> Option<&Xart> {
        self.xart.as_ref()
    }

    /// Whether application-service requests await the DMA step.
    pub fn dma_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Answer the queued application-service requests through `port`. A
    /// refusal or DMA fault stops before that request's reply.
    pub fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        for frame in core::mem::take(&mut self.pending) {
            let xart = self
                .xart
                .as_mut()
                .ok_or("SEP application service has no native handler")?;
            let mut payload = Ool {
                buffers: self.buffers.iter().find(|b| b.service() == frame.service),
                port: &mut *port,
                read: 0,
            };
            let reply = xart.request(frame, &mut payload, entropy)?;
            outbox.push(reply.mailbox());
        }
        Ok(())
    }

    /// Advertise `catalog` once OS active is reported. Its services' frames
    /// still need native handlers; an empty catalog advertises nothing.
    pub fn with_catalog(mut self, catalog: Catalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// The shared-memory aggregate the AP mapped for the SEP, once received.
    pub fn region(&self) -> Option<Region> {
        self.region
    }

    /// Whether the SEP has reported its OS active to the control endpoint.
    pub fn os_active_sent(&self) -> bool {
        self.os_active_sent
    }

    pub fn power(&self) -> Power {
        self.power
    }

    /// Whether the AP announced it is ready to sleep (`cmsgAP_SLEEP_READY`).
    pub fn ap_sleep_ready(&self) -> bool {
        self.ap_sleep_ready
    }

    /// The OOL buffers an application service registered, if any.
    pub fn buffers(&self, service: u8) -> Option<&Buffers> {
        self.buffers.iter().find(|b| b.service() == service)
    }

    /// Dispatch an AP-sent frame in the active phase. Boot (0xfe) records the
    /// shared-memory region and reports OS active once; control requests are
    /// answered once that has happened; other traffic refuses.
    pub fn receive(
        &mut self,
        frame: Frame,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        match frame.service {
            message::BOOT => {
                let region = Region::from_message(frame.mailbox())?;
                self.region = Some(region);
                if !self.os_active_sent {
                    outbox.push(control::notification(control::OS_ACTIVE, 0).mailbox());
                    outbox.extend(
                        self.catalog
                            .advertisements()
                            .into_iter()
                            .map(Frame::mailbox),
                    );
                    self.os_active_sent = true;
                }
                Ok(())
            }
            message::CONTROL => self.control(frame, entropy, outbox),
            message::DISCOVERY => {
                Err("SEP discovery is advertised by the SEP, not received from the AP")
            }
            message::ROM => Err("SEPROM commands are not valid once sepOS is active"),
            service if self.xart.is_some() && self.catalog.service(service).is_ok() => {
                if !self.os_active_sent {
                    return Err("SEP service request before sepOS reported OS active");
                }
                if self.power != Power::Awake {
                    return Err("SEP service request while the SEP sleeps or naps");
                }
                self.pending.push(frame);
                Ok(())
            }
            _ => Err("SEP application service is not modeled"),
        }
    }

    fn control(
        &mut self,
        frame: Frame,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        if !self.os_active_sent {
            return Err("SEP control request before sepOS mapped its shared memory");
        }
        let request = Request::decode(frame)?;
        if self.power != Power::Awake && !matches!(request, Request::Wake | Request::WakeFromNap) {
            return Err("SEP control request while the SEP sleeps or naps");
        }
        let data = match request {
            Request::Nop => Some(0),
            Request::Ool => {
                let service = self.catalog.service(frame.parameter)?;
                let input = matches!(
                    frame.opcode,
                    control::SET_OOL_IN_LENGTH | control::SET_OOL_IN_ADDRESS
                );
                let length = matches!(
                    frame.opcode,
                    control::SET_OOL_IN_LENGTH | control::SET_OOL_OUT_LENGTH
                );
                if length && !service.accepts(input, frame.data, SEP_PAGE_BYTES) {
                    return Err("SEP OOL length is outside the service's advertised pages");
                }
                let index = match self
                    .buffers
                    .iter()
                    .position(|b| b.service() == frame.parameter)
                {
                    Some(index) => index,
                    None => {
                        self.buffers.push(Buffers::new(frame.parameter)?);
                        self.buffers.len() - 1
                    }
                };
                self.buffers[index].record(frame)?;
                Some(0)
            }
            Request::Sleep(kind) => {
                self.power = Power::Asleep(kind);
                Some(0)
            }
            Request::Wake => {
                if !matches!(self.power, Power::Asleep(_)) {
                    return Err("SEP wake without a preceding sleep");
                }
                self.power = Power::Awake;
                self.ap_sleep_ready = false;
                Some(0)
            }
            Request::Nap => {
                self.power = Power::Napping;
                None
            }
            Request::WakeFromNap => {
                if self.power != Power::Napping {
                    return Err("SEP nap wake while the SEP is not napping");
                }
                self.power = Power::Awake;
                outbox.push(control::notification(control::NAP_AWAKE, 0).mailbox());
                None
            }
            Request::NapOk => {
                return Err("SEP nap acknowledgement without a SEP nap request");
            }
            Request::ApSleepReady => {
                self.ap_sleep_ready = true;
                None
            }
            Request::SecurityMode => {
                let mode = self.security.ok_or(
                    "SEP security mode is unknown: /chosen lacks the AP's effective production status and security mode",
                )?;
                Some(u32::from(mode.production) | u32::from(mode.secure) << 1)
            }
            Request::Entropy => {
                let mut bytes = [0; 4];
                entropy.fill(&mut bytes)?;
                Some(u32::from_le_bytes(bytes))
            }
            // restored_external announces an Erase Install before it
            // initializes the gigalocker: the SEP erases its anti-replay
            // state.
            Request::EraseInstall => {
                self.xart
                    .as_mut()
                    .ok_or("SEP erase-install needs the xART store")?
                    .store_mut()
                    .erase()?;
                Some(0)
            }
            Request::SelfTest => return Err("SEP self test is not modeled"),
            Request::TtyIn(_) => return Err("SEP console input is not modeled"),
            Request::RelayDma(_) => {
                return Err("SEP relay DMA exists only on boards with pcie-up-interrupts");
            }
            Request::Panic => return Err("the AP requested a SEP panic"),
        };
        if let Some(data) = data {
            outbox.push(control::reply(frame, Status::Success, data).mailbox());
        }
        Ok(())
    }
}

/// A service's OOL buffers as its request payload. Input is read in order
/// from the start of the AP-to-SEP buffer; output starts the SEP-to-AP one.
struct Ool<'a, 'p, 'm, 'n> {
    buffers: Option<&'a Buffers>,
    port: &'p mut Port<'m, 'n>,
    read: u64,
}

fn dma_refusal(error: DmaError) -> &'static str {
    match error {
        DmaError::Unsupported(reason) => reason,
        DmaError::Fault(_) => "SEP service OOL DMA fault in dart-sep",
        DmaError::Memory => "SEP service OOL buffer is outside guest RAM",
    }
}

impl Payload for Ool<'_, '_, '_, '_> {
    fn input(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
        let buffers = self
            .buffers
            .ok_or("SEP service request before its OOL buffers are registered")?;
        buffers
            .read_input(self.port, self.read, bytes)
            .map_err(dma_refusal)?;
        self.read += bytes.len() as u64;
        Ok(())
    }

    fn output(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        let buffers = self
            .buffers
            .ok_or("SEP service reply before its OOL buffers are registered")?;
        buffers
            .write_output(self.port, 0, bytes)
            .map_err(dma_refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::sep::endpoint::Service;

    fn shm(address: u64, pages: u16) -> Frame {
        Frame {
            service: message::BOOT,
            tag: 0,
            opcode: pages as u8,
            parameter: (pages >> 8) as u8,
            data: (address >> 12) as u32,
        }
    }

    fn control(tag: u8, opcode: u8, parameter: u8, data: u32) -> Frame {
        Frame {
            service: message::CONTROL,
            tag,
            opcode,
            parameter,
            data,
        }
    }

    fn counter() -> impl FnMut(&mut [u8]) -> Result<(), &'static str> {
        let mut next = 0u8;
        move |bytes: &mut [u8]| {
            for byte in bytes {
                next = next.wrapping_add(1);
                *byte = next;
            }
            Ok(())
        }
    }

    /// Service 9, taking one or two pages each way.
    fn catalog() -> Catalog {
        Catalog::new(alloc::vec![Service {
            id: 9,
            name: u32::from_be_bytes(*b"test"),
            capacities: [1, 2, 1, 2],
        }])
        .unwrap()
    }

    fn store() -> Nonces<Box<dyn Backend>> {
        let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32]).unwrap();
        let backend: Box<dyn Backend> = Box::new(super::super::store::Volatile::default());
        Nonces::provision(&roots, backend).unwrap()
    }

    fn active(security: Option<SecurityMode>) -> SepOs {
        let mut os = SepOs::new(security).with_catalog(catalog());
        let mut outbox = Vec::new();
        os.receive(shm(0x1234_5000, 0x20), &mut counter(), &mut outbox)
            .unwrap();
        os
    }

    fn reply(os: &mut SepOs, frame: Frame) -> Result<Vec<Frame>, &'static str> {
        let mut outbox = Vec::new();
        os.receive(frame, &mut counter(), &mut outbox)?;
        Ok(outbox
            .into_iter()
            .map(|m| Frame::from_mailbox(m).unwrap())
            .collect())
    }

    #[test]
    fn mapping_shared_memory_reports_os_active_exactly_once() {
        let mut os = SepOs::new(None);
        assert!(!os.os_active_sent());
        let first = reply(&mut os, shm(0x1234_5000, 0x20)).unwrap();
        assert_eq!(
            os.region(),
            Some(Region {
                address: 0x1234_5000,
                bytes: 0x20 << 12,
            })
        );
        assert_eq!(first, [control::notification(control::OS_ACTIVE, 0)]);
        assert!(os.os_active_sent());
        // A cataloged service is advertised after OS active, name first.
        let mut os = SepOs::new(None).with_catalog(catalog());
        let first = reply(&mut os, shm(0x1234_5000, 0x20)).unwrap();
        assert_eq!(first[0], control::notification(control::OS_ACTIVE, 0));
        assert_eq!(first[1..], catalog().advertisements()[..]);
        assert_eq!((first[1].opcode, first[2].opcode), (0, 1));
        // A second shared-memory frame (wake remap) does not re-announce.
        assert!(reply(&mut os, shm(0x2000_0000, 0x10)).unwrap().is_empty());
    }

    #[test]
    fn tagged_control_requests_are_answered_with_their_tag_and_status() {
        let mode = SecurityMode {
            production: true,
            secure: true,
        };
        let mut os = active(Some(mode));
        let nop = control(3, control::NOP, 0, 0);
        assert_eq!(
            reply(&mut os, nop).unwrap(),
            [control::reply(nop, Status::Success, 0)]
        );
        let mode_request = control(4, control::SECURITY_MODE, 0, 0);
        assert_eq!(reply(&mut os, mode_request).unwrap()[0].data, 0b11);
        let entropy = control(5, control::ENTROPY, 0, 0);
        assert_eq!(
            reply(&mut os, entropy).unwrap(),
            [control::reply(entropy, Status::Success, 0x0403_0201)]
        );
        // OOL registration: length, then page address, owned by service 9.
        reply(&mut os, control(6, control::SET_OOL_IN_LENGTH, 9, 0x4000)).unwrap();
        reply(
            &mut os,
            control(7, control::SET_OOL_IN_ADDRESS, 9, 0x8_0000),
        )
        .unwrap();
        assert!(os.buffers(9).is_some());
        assert!(os.buffers(10).is_none());
        // Unadvertised owners and lengths outside the pages refuse.
        assert!(reply(&mut os, control(8, control::SET_OOL_IN_LENGTH, 10, 0x4000)).is_err());
        assert!(reply(&mut os, control(8, control::SET_OOL_OUT_LENGTH, 9, 0xc000)).is_err());
        assert!(reply(&mut os, control(8, control::SET_OOL_OUT_LENGTH, 9, 0x8000)).is_ok());
        // An unknown security mode refuses rather than guess one.
        let mut unknown = active(None);
        assert!(reply(&mut unknown, mode_request).is_err());
    }

    #[test]
    fn sleep_nap_and_wake_follow_the_ap_power_sequence() {
        let mut os = active(None);
        reply(&mut os, control(1, control::SLEEP, 2, 0)).unwrap();
        assert_eq!(os.power(), Power::Asleep(2));
        // Asleep, only a wake is serviced.
        assert!(reply(&mut os, control(2, control::NOP, 0, 0)).is_err());
        reply(&mut os, control(3, control::WAKE, 0, 0)).unwrap();
        assert_eq!(os.power(), Power::Awake);
        assert!(reply(&mut os, control(4, control::WAKE, 0, 0)).is_err());
        // AP nap: no reply; the nap wake word is answered by NAP_AWAKE.
        assert!(
            reply(&mut os, control(0, control::NAP, 0, 0))
                .unwrap()
                .is_empty()
        );
        assert_eq!(os.power(), Power::Napping);
        assert_eq!(
            reply(&mut os, control(0, control::WAKE_FROM_NAP, 0, 0)).unwrap(),
            [control::notification(control::NAP_AWAKE, 0)]
        );
        assert!(reply(&mut os, control(0, control::WAKE_FROM_NAP, 0, 0)).is_err());
        assert!(
            reply(&mut os, control(0, control::AP_SLEEP_READY, 0, 0))
                .unwrap()
                .is_empty()
        );
        assert!(os.ap_sleep_ready());
    }

    struct Identity;
    impl crate::platform::dma::Iommu for Identity {
        fn page(&self) -> u64 {
            0x4000
        }
        fn translate(
            &mut self,
            _: &mut dyn crate::platform::dma::Memory,
            _: usize,
            iova: u64,
            _: u64,
            _: bool,
            _: &mut crate::platform::apple::bus::Access<'_>,
        ) -> Result<u64, DmaError> {
            Ok(iova)
        }
    }

    fn dma(
        os: &mut SepOs,
        ram: &mut crate::platform::dma::tests::Ram,
    ) -> Result<Vec<Frame>, &'static str> {
        let mut latch = crate::platform::apple::interrupt::InterruptLatch::new();
        let mut access = crate::platform::apple::bus::Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Identity,
            stream: 0,
            memory: ram,
            access: &mut access,
        };
        let mut outbox = Vec::new();
        os.dma(
            &mut port,
            &mut |bytes: &mut [u8]| {
                bytes.fill(0x5a);
                Ok(())
            },
            &mut outbox,
        )?;
        Ok(outbox
            .into_iter()
            .map(|m| Frame::from_mailbox(m).unwrap())
            .collect())
    }

    #[test]
    fn xart_requests_are_answered_after_their_ool_input_is_read() {
        let mut os = SepOs::new(None).with_services(store()).unwrap();
        let advertised = reply(&mut os, shm(0x1234_5000, 0x20)).unwrap();
        // OS active, then name and capacities for each of xarm and xars.
        assert_eq!(advertised.len(), 5);
        assert_eq!(advertised[1].data, xart::MASTER);
        assert_eq!(advertised[3].data, xart::SLAVE);
        let request = xart::XartMessage {
            service: xart::SLAVE_ID,
            tag: 4,
            op: 8,
            length: 16,
            flags: 0,
            slot: 0,
            reserved: 0,
        }
        .frame();
        // Without registered buffers the request is queued, then refuses.
        assert!(reply(&mut os, request).unwrap().is_empty());
        assert!(os.dma_pending());
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x10000);
        assert!(dma(&mut os, &mut ram).is_err());
        // The AP registers one 0x8000-byte buffer each way, then sends.
        for (tag, opcode, data) in [
            (1, control::SET_OOL_IN_LENGTH, 0x8000),
            (2, control::SET_OOL_IN_ADDRESS, 0x100),
            (3, control::SET_OOL_OUT_LENGTH, 0x8000),
            (4, control::SET_OOL_OUT_ADDRESS, 0x108),
        ] {
            reply(&mut os, control(tag, opcode, xart::SLAVE_ID, data)).unwrap();
        }
        ram.bytes[..16].copy_from_slice(&[0x5a; 16]);
        assert!(reply(&mut os, request).unwrap().is_empty());
        let answer = dma(&mut os, &mut ram).unwrap();
        assert_eq!(
            answer,
            [xart::XartMessage {
                op: 0,
                length: 0,
                ..xart::XartMessage::from_frame(request)
            }
            .frame()]
        );
        assert_eq!(os.xart().unwrap().os_uuid(), Some(&[0x5a; 16][..]));
        assert!(!os.dma_pending());
        // The nonce comes from the store; the Erase Install announcement
        // erases it.
        let nonce = |op| {
            xart::XartMessage {
                op,
                length: 0,
                ..xart::XartMessage::from_frame(request)
            }
            .frame()
        };
        reply(&mut os, nonce(0x0f)).unwrap();
        assert_eq!(
            xart::XartMessage::from_frame(dma(&mut os, &mut ram).unwrap()[0]).length,
            20
        );
        assert_eq!(ram.bytes[0x8000..0x8014], [0x5a; 20]);
        assert_eq!(
            reply(&mut os, control(5, control::ERASE_INSTALL, 0, 0)).unwrap(),
            [control::reply(
                control(5, control::ERASE_INSTALL, 0, 0),
                Status::Success,
                0
            )]
        );
        reply(&mut os, nonce(0x10)).unwrap();
        assert!(dma(&mut os, &mut ram).is_err());
        // An unrecovered operation refuses with no reply.
        reply(&mut os, nonce(18)).unwrap();
        assert!(dma(&mut os, &mut ram).is_err());
    }

    #[test]
    fn unmodeled_inbound_traffic_refuses_without_faking_a_reply() {
        // Control before shared memory is mapped refuses.
        let mut os = SepOs::new(None);
        assert!(reply(&mut os, control(1, control::NOP, 0, 0)).is_err());
        let mut os = active(None);
        for frame in [
            control(1, control::SELF_TEST, 0, 0),
            control(1, control::TTY_IN, 0x41, 0),
            control(1, 26, 0, 0),
            control(1, control::ERASE_INSTALL, 0, 0),
            control(1, control::SEPOS_PANIC, 0, 0),
            control(0, control::NAP_OK, 0, 0),
            control(1, 0x40, 0, 0),
            Frame {
                service: message::DISCOVERY,
                ..control(1, 0, 0, 0)
            },
            Frame {
                service: message::ROM,
                ..control(1, 0, 0, 0)
            },
            Frame {
                service: 0x12,
                ..control(1, 0, 0, 0)
            },
        ] {
            assert!(reply(&mut os, frame).is_err(), "{frame:?}");
        }
        // A malformed shared-memory frame (zero length) is refused.
        assert!(reply(&mut SepOs::new(None), shm(0x1000, 0)).is_err());
    }
}
