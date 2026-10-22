//! The emulated sepOS active phase. Stela is the SEP, with its own keys.
//!
//! Once SEPROM accepts the delivered container under Stela's trust policy
//! (see [`super::firmware`]), this phase speaks the AP-facing boot-completion
//! protocol. `AppleSEPBooter::bootSEP` 0x2d73ddc..0x2d73e68 maps the aggregate
//! shared-memory buffer and sends its slave address and size on service 0xfe;
//! the SEP validates its directory through dart-sep before notifying the
//! control endpoint that the OS is active. That
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
//! client registered; the reply follows only once that has succeeded. A
//! refused request stops a strict run; a graceful one sends the service
//! protocol's failure answer, unless the request may already have taken
//! effect ([`super::transaction`]).
use super::super::asc::Message;
use super::{
    Entropy, SecurityMode,
    boot_policy::{self, BootPolicy},
    control::{self, Request, Status},
    endpoint::Catalog,
    keystore::{self, KeyStore},
    message::{self, Frame},
    observe::{self, Journal},
    ool::Buffers,
    shared::{Layout, Region},
    store::{Backend, Nonces},
    transaction::{Payload, Refusal},
    xart::{self, Xart},
};
use crate::platform::dma::{DmaError, Port};
use alloc::{boxed::Box, collections::VecDeque, format, string::String, vec::Vec};

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
    pending_region: Option<Region>,
    layout: Option<Layout>,
    os_active_sent: bool,
    security: Option<SecurityMode>,
    power: Power,
    ap_sleep_ready: bool,
    buffers: Vec<Buffers>,
    catalog: Catalog,
    services: Option<Services>,
    /// Application-service requests awaiting the DMA step, in arrival order.
    pending: VecDeque<Frame>,
    /// When observing (`--sep-observe`), the recorded `sks`/`pnon`/`scrd`
    /// traffic; `scrd` is then advertised and its requests never answered.
    observe: Option<Journal>,
    /// Strict mode ([`Self::set_strict`]): a refused or observed `scrd`
    /// request stops the boot. Otherwise a refusal gets its failure answer,
    /// an observed request none, and the boot goes on.
    strict: bool,
}

/// The native application services behind the catalog.
struct Services {
    xart: Xart,
    keystore: KeyStore,
    boot_policy: BootPolicy,
}

/// The SEP page that scales discovery capacities: 16 KiB, since
/// `AppleSEPManager::start` 0x2d67308 selects it from the SEP node's `aarch64`
/// property, which `soc::sep_device` requires.
pub const SEP_PAGE_BYTES: u32 = 0x4000;
/// Native implementation resource bound, not a firmware protocol constant.
const MAX_PENDING_REQUESTS: usize = 256;

impl SepOs {
    pub fn new(security: Option<SecurityMode>) -> Self {
        Self {
            region: None,
            pending_region: None,
            layout: None,
            os_active_sent: false,
            security,
            power: Power::Awake,
            ap_sleep_ready: false,
            buffers: Vec::new(),
            catalog: Catalog::empty(),
            services: None,
            pending: VecDeque::new(),
            observe: None,
            strict: true,
        }
    }

    /// Strict mode (the default) stops at each refused service request, and
    /// at each observed `scrd` request once it is recorded. Graceful mode
    /// answers a refusal with its failure answer and leaves an observed
    /// request unanswered, so the kernel client takes its own timeout path
    /// and the run records the requests that follow: a diagnostic exception
    /// to the error-reply rule (docs/design/runtime.md "Unsupported
    /// operations"), never a reply.
    pub fn set_strict(&mut self, strict: bool) {
        self.strict = strict;
    }

    /// The SEP's native services, advertised once OS active is reported:
    /// the xART pair over the anti-replay store `store`, the keystore and
    /// BootPolicy. With `observe`, their traffic is journaled and `scrd` is
    /// also advertised so its kernel client binds; its requests are
    /// recorded and never answered (a diagnostic mode: it qualifies nothing
    /// beyond its log).
    pub fn with_services(
        mut self,
        store: Nonces<Box<dyn Backend>>,
        observe: bool,
    ) -> Result<Self, &'static str> {
        let mut services = xart::services().to_vec();
        services.extend([keystore::service(), boot_policy::service()]);
        if observe {
            services.extend(observe::services());
            self.observe = Some(Journal::default());
        }
        self.catalog = Catalog::new(services)?;
        self.services = Some(Services {
            xart: Xart::new(store),
            keystore: KeyStore::default(),
            boot_policy: BootPolicy::new(None),
        });
        Ok(self)
    }

    /// Drain the observed `sks`/`pnon`/`scrd` traffic recorded this run.
    pub fn observations(&mut self) -> Vec<String> {
        self.observe
            .as_mut()
            .map(|journal| journal.drain().collect())
            .unwrap_or_default()
    }

    /// The xART service state, when installed.
    pub fn xart(&self) -> Option<&Xart> {
        self.services.as_ref().map(|services| &services.xart)
    }

    /// The keystore service state, when installed.
    pub fn keystore(&self) -> Option<&KeyStore> {
        self.services.as_ref().map(|services| &services.keystore)
    }

    /// Whether application-service requests await the DMA step.
    pub fn dma_pending(&self) -> bool {
        self.pending_region.is_some() || !self.pending.is_empty()
    }

    /// Answer the queued application-service requests through `port`. A
    /// refusal or DMA fault returns its reason instead of the reply, after
    /// queueing its failure answer outside strict mode; an observed `scrd`
    /// request is recorded and gets none.
    pub fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        if let Some(region) = self.pending_region {
            let layout =
                Layout::read(port, region, u64::from(SEP_PAGE_BYTES)).map_err(dma_refusal)?;
            self.region = Some(region);
            self.layout = Some(layout);
            self.pending_region = None;
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
            return Ok(());
        }
        // One request per DMA step: ASC publishes the whole produced outbox
        // only on success. A later request's failure must not discard an
        // earlier committed operation's reply. A failed request may
        // already have committed durable state before output DMA failed;
        // do not replay it or silently discard unrelated later requests.
        let Some(frame) = self.pending.pop_front() else {
            return Ok(());
        };
        if self.observe.is_some()
            && let Some(name) = observe::name(frame.service)
        {
            // Record the request: its frame plus a bounded prefix of its
            // OOL input.
            self.record(name, frame, &mut *port);
        }
        if frame.service == observe::CREDENTIALS_ID {
            // Observation never answers scrd.
            return if self.strict {
                Err(observe::REFUSAL)
            } else {
                Ok(())
            };
        }
        let services = self
            .services
            .as_mut()
            .ok_or("SEP application service has no native handler")?;
        let mut payload = Ool {
            buffers: self.buffers.iter().find(|b| b.service() == frame.service),
            port: &mut *port,
            read: 0,
        };
        let result = match frame.service {
            xart::MASTER_ID | xart::SLAVE_ID => services.xart.request(frame, &mut payload, entropy),
            keystore::ID => services.keystore.request(frame, &mut payload),
            boot_policy::ID => services.boot_policy.request(frame, &mut payload),
            _ => Err(Refusal::unanswerable(
                "SEP application service has no native handler",
            )),
        };
        match result {
            Ok(reply) => {
                outbox.push(reply.mailbox());
                Ok(())
            }
            Err(refusal) => {
                // Graceful: the failure answer, once its bytes are written.
                if !self.strict
                    && let Some(answer) = refusal.answer
                    && (answer.output.is_empty() || payload.output(&answer.output).is_ok())
                {
                    outbox.push(answer.frame.mailbox());
                }
                Err(refusal.reason)
            }
        }
    }

    /// Record one observed `sks`/`pnon`/`scrd` request: its frame fields and,
    /// when its OOL input buffer is registered, a bounded hex prefix of the
    /// bytes the kernel placed there. This reads memory only; it writes no
    /// reply.
    fn record(&mut self, name: &str, frame: Frame, port: &mut Port<'_, '_>) {
        let mut line = format!(
            "{name} tag={} op={} param={:#x} data={:#010x}",
            frame.tag, frame.opcode, frame.parameter, frame.data
        );
        if let Some(buffers) = self.buffers.iter().find(|b| b.service() == frame.service) {
            let available = buffers.input_len();
            if available == 0 {
                line.push_str(" input=unregistered");
            } else {
                let take = available.min(observe::INPUT_PREFIX as u64) as usize;
                let mut bytes = alloc::vec![0; take];
                match buffers.read_input(port, 0, &mut bytes) {
                    Ok(()) => {
                        line.push_str(&format!(" input[{available}]={}", observe::hex(&bytes)));
                    }
                    Err(_) => line.push_str(" input=unreadable"),
                }
            }
        } else {
            line.push_str(" input=unregistered");
        }
        if let Some(journal) = self.observe.as_mut() {
            journal.record(line);
        }
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

    /// Directory metadata last validated through dart-sep. This makes no
    /// claim about an unrecovered channel's content or authentication.
    pub fn layout(&self) -> Option<&Layout> {
        self.layout.as_ref()
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
    /// shared-memory region for validation in the DMA step. Control requests
    /// are answered once that reports OS active; other traffic refuses.
    pub fn receive(
        &mut self,
        frame: Frame,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        match frame.service {
            message::BOOT => {
                if self.pending_region.is_some() || !self.pending.is_empty() {
                    return Err("SEP shared-memory remap while DMA work is pending");
                }
                let region = Region::from_message(frame.mailbox())?;
                self.pending_region = Some(region);
                Ok(())
            }
            message::CONTROL => self.control(frame, entropy, outbox),
            message::DISCOVERY => {
                Err("SEP discovery is advertised by the SEP, not received from the AP")
            }
            message::ROM => Err("SEPROM commands are not valid once sepOS is active"),
            service if self.services.is_some() && self.catalog.service(service).is_ok() => {
                if !self.os_active_sent {
                    return Err("SEP service request before sepOS reported OS active");
                }
                if self.pending_region.is_some() {
                    return Err("SEP service request while shared-memory remap is pending");
                }
                if self.power != Power::Awake {
                    return Err("SEP service request while the SEP sleeps or naps");
                }
                if self.pending.len() == MAX_PENDING_REQUESTS {
                    return Err("SEP application request queue exceeds the resource bound");
                }
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.service == frame.service && pending.tag == frame.tag)
                {
                    return Err("SEP application request repeats an outstanding service/tag");
                }
                self.pending.push_back(frame);
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
        if self.pending_region.is_some() {
            return Err("SEP control request while shared-memory remap is pending");
        }
        let request = Request::decode(frame)?;
        if self.power != Power::Awake && !matches!(request, Request::Wake | Request::WakeFromNap) {
            return Err("SEP control request while the SEP sleeps or naps");
        }
        let data = match request {
            Request::Nop => Some(0),
            Request::Ool => {
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.service == frame.parameter)
                {
                    return Err("SEP OOL registration while its service has pending requests");
                }
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
                if !self.pending.is_empty() {
                    return Err("SEP sleep while application requests are pending is not modeled");
                }
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
                if !self.pending.is_empty() {
                    return Err("SEP nap while application requests are pending is not modeled");
                }
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
                if !self.pending.is_empty() {
                    return Err(
                        "SEP erase-install while application requests are pending is not modeled",
                    );
                }
                self.services
                    .as_mut()
                    .ok_or("SEP erase-install needs the xART store")?
                    .xart
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
        let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32], 0xa5a5_0002).unwrap();
        let backend: Box<dyn Backend> = Box::new(super::super::store::Volatile::default());
        Nonces::provision(&roots, backend).unwrap()
    }

    fn active(security: Option<SecurityMode>) -> SepOs {
        let mut os = SepOs::new(security).with_catalog(catalog());
        map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
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

    fn map_shared(os: &mut SepOs, frame: Frame) -> Result<Vec<Frame>, &'static str> {
        let region = Region::from_message(frame.mailbox())?;
        assert!(reply(os, frame)?.is_empty());
        let mut ram = crate::platform::dma::tests::Ram::new(region.address, 0x4000);
        ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
        dma(os, &mut ram)
    }

    #[test]
    fn mapping_shared_memory_reports_os_active_exactly_once() {
        let mut os = SepOs::new(None);
        assert!(!os.os_active_sent());
        let first = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        assert_eq!(
            os.region(),
            Some(Region {
                address: 0x1234_4000,
                bytes: 0x20 << 12,
            })
        );
        assert_eq!(first, [control::notification(control::OS_ACTIVE, 0)]);
        assert!(os.os_active_sent());
        // A cataloged service is advertised after OS active, name first.
        let mut os = SepOs::new(None).with_catalog(catalog());
        let first = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        assert_eq!(first[0], control::notification(control::OS_ACTIVE, 0));
        assert_eq!(first[1..], catalog().advertisements()[..]);
        assert_eq!((first[1].opcode, first[2].opcode), (0, 1));
        // A second shared-memory frame (wake remap) does not re-announce.
        assert!(
            map_shared(&mut os, shm(0x2000_0000, 0x10))
                .unwrap()
                .is_empty()
        );
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

    /// One DMA step: its result and every frame it produced, which a failed
    /// step may also have.
    fn dma_step(
        os: &mut SepOs,
        ram: &mut crate::platform::dma::tests::Ram,
    ) -> (Result<(), &'static str>, Vec<Frame>) {
        let mut latch = crate::platform::apple::interrupt::InterruptLatch::new();
        let mut access = crate::platform::apple::bus::Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Identity,
            stream: 0,
            memory: ram,
            access: &mut access,
        };
        let mut outbox = Vec::new();
        let result = os.dma(
            &mut port,
            &mut |bytes: &mut [u8]| {
                bytes.fill(0x5a);
                Ok(())
            },
            &mut outbox,
        );
        let frames = outbox
            .into_iter()
            .map(|m| Frame::from_mailbox(m).unwrap())
            .collect();
        (result, frames)
    }

    fn dma(
        os: &mut SepOs,
        ram: &mut crate::platform::dma::tests::Ram,
    ) -> Result<Vec<Frame>, &'static str> {
        let (result, frames) = dma_step(os, ram);
        result.map(|()| frames)
    }

    /// Register `service`'s OOL buffers: `input` bytes at 0x10_0000 and
    /// `output` bytes right after.
    fn register(os: &mut SepOs, service: u8, input: u32, output: u32) {
        for (tag, opcode, data) in [
            (1, control::SET_OOL_IN_LENGTH, input),
            (2, control::SET_OOL_IN_ADDRESS, 0x100),
            (3, control::SET_OOL_OUT_LENGTH, output),
            (4, control::SET_OOL_OUT_ADDRESS, 0x100 + (input >> 12)),
        ] {
            reply(os, control(tag, opcode, service, data)).unwrap();
        }
    }

    #[test]
    fn xart_requests_are_answered_after_their_ool_input_is_read() {
        let mut os = SepOs::new(None).with_services(store(), false).unwrap();
        let advertised = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        // OS active, then name and capacities for each of xarm, xars, sks
        // and pnon.
        assert_eq!(advertised.len(), 9);
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
    fn one_failed_request_does_not_discard_other_transactions_or_their_replies() {
        let mut os = SepOs::new(None).with_services(store(), false).unwrap();
        map_shared(&mut os, shm(0x4000, 4)).unwrap();
        for (tag, opcode, data) in [
            (1, control::SET_OOL_IN_LENGTH, 0x8000),
            (2, control::SET_OOL_IN_ADDRESS, 0x100),
        ] {
            reply(&mut os, control(tag, opcode, xart::SLAVE_ID, data)).unwrap();
        }
        let request = |tag, op, length| {
            xart::XartMessage {
                service: xart::SLAVE_ID,
                tag,
                op,
                length,
                flags: 0,
                slot: 0,
                reserved: 0,
            }
            .frame()
        };
        for frame in [request(1, 8, 16), request(2, 18, 0), request(3, 8, 16)] {
            reply(&mut os, frame).unwrap();
        }
        assert!(reply(&mut os, request(1, 8, 16)).is_err());
        assert!(
            reply(
                &mut os,
                control(3, control::SET_OOL_IN_LENGTH, xart::SLAVE_ID, 0x8000)
            )
            .is_err()
        );
        assert!(reply(&mut os, control(3, control::SLEEP, 0, 0)).is_err());
        assert_eq!(os.power(), Power::Awake);
        assert!(reply(&mut os, shm(0x8000, 4)).is_err());
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x8000);
        ram.bytes[..16].fill(0x5a);
        let first = dma(&mut os, &mut ram).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].tag, 1);
        assert!(os.dma_pending());
        assert_eq!(
            dma(&mut os, &mut ram),
            Err("xART commit-hash types are not recovered")
        );
        assert!(os.dma_pending());
        let third = dma(&mut os, &mut ram).unwrap();
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].tag, 3);
        assert!(!os.dma_pending());
        assert_eq!(os.xart().unwrap().os_uuid(), Some(&[0x5a; 16][..]));
    }

    #[test]
    fn a_graceful_xart_refusal_is_answered_enotsup_from_the_dma_step() {
        let mut os = SepOs::new(None).with_services(store(), false).unwrap();
        os.set_strict(false);
        map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        let commit_hash = xart::XartMessage {
            service: xart::SLAVE_ID,
            tag: 9,
            op: 18,
            length: 0,
            flags: 0,
            slot: 0,
            reserved: 0,
        }
        .frame();
        reply(&mut os, commit_hash).unwrap();
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x1000);
        assert_eq!(
            dma_step(&mut os, &mut ram),
            (
                Err("xART commit-hash types are not recovered"),
                alloc::vec![xart::unsupported(commit_hash)]
            )
        );
    }

    #[test]
    fn remap_validates_before_replacing_the_active_layout() {
        let mut os = active(None);
        let previous = os.layout().unwrap().clone();
        assert!(reply(&mut os, shm(0x8000, 4)).unwrap().is_empty());
        assert_eq!(os.region(), Some(previous.region));
        assert!(reply(&mut os, control(1, control::NOP, 0, 0)).is_err());
        let mut ram = crate::platform::dma::tests::Ram::new(0x8000, 0x4000);
        // A zero-filled directory has no null terminator and must not
        // replace the known layout, even after OS-active was published.
        assert!(dma(&mut os, &mut ram).is_err());
        assert_eq!(os.layout(), Some(&previous));
        assert!(os.dma_pending());
        ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
        assert!(dma(&mut os, &mut ram).unwrap().is_empty());
        assert_eq!(os.region().unwrap().address, 0x8000);
        assert!(!os.dma_pending());
        assert_eq!(
            reply(&mut os, control(1, control::NOP, 0, 0))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_keystore_startup_is_answered_through_its_ool_buffers() {
        let mut os = SepOs::new(None).with_services(store(), false).unwrap();
        map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        register(&mut os, keystore::ID, 0x8000, 0x8000);
        let request = keystore::tests::message(1, 0, 1, &[]);
        let frame = Frame {
            service: keystore::ID,
            tag: keystore::GET_CAPABILITIES,
            opcode: 3,
            parameter: 0,
            data: (request.len() as u32) << 16,
        };
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x10000);
        ram.bytes[..request.len()].copy_from_slice(&request);
        assert!(reply(&mut os, frame).unwrap().is_empty());
        let answer = dma(&mut os, &mut ram).unwrap();
        assert_eq!(
            answer,
            [Frame {
                tag: keystore::GET_CAPABILITIES | keystore::REPLY,
                data: 92 << 16,
                ..frame
            }]
        );
        // The negotiated version, 2, follows the header and result.
        assert_eq!(ram.bytes[0x8000 + 80..0x8000 + 88], 2u64.to_le_bytes());
        assert!(os.keystore().unwrap().environment().is_none());
    }

    #[test]
    fn native_and_observed_services_are_advertised_and_journaled() {
        let mut os = SepOs::new(None).with_services(store(), true).unwrap();
        let advertised = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        // OS active, then xarm, xars, sks, pnon and the observed scrd.
        assert_eq!(advertised.len(), 1 + 2 * 5);
        let names: Vec<u32> = advertised[1..]
            .iter()
            .filter(|f| f.opcode == 0)
            .map(|f| f.data)
            .collect();
        assert!(names.contains(&u32::from_be_bytes(*b"sks\0")));
        assert!(names.contains(&u32::from_be_bytes(*b"pnon")));
        assert!(names.contains(&u32::from_be_bytes(*b"scrd")));
        // BootPolicy's buffers, then its current-OS-type command.
        register(&mut os, boot_policy::ID, 0x1c000, 0x14000);
        let request = Frame {
            service: boot_policy::ID,
            tag: 2,
            opcode: 0,
            parameter: 0,
            data: 32,
        };
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x30000);
        ram.bytes[..4].copy_from_slice(b"hcPB");
        ram.bytes[4] = 0x3e;
        // Strict: recorded, then refused with no answer.
        assert!(reply(&mut os, request).unwrap().is_empty());
        assert_eq!(dma_step(&mut os, &mut ram).1, []);
        let lines = os.observations();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("pnon tag=2 op=0"), "{}", lines[0]);
        assert!(lines[0].contains("686350423e000000"), "{}", lines[0]);
        // Graceful: the not-supported reply header answers it.
        os.set_strict(false);
        assert!(reply(&mut os, request).unwrap().is_empty());
        let (result, answer) = dma_step(&mut os, &mut ram);
        assert!(result.is_err());
        assert_eq!(answer, [request]);
        assert_eq!(ram.bytes[0x1c000..0x1c004], *b"hrPB");
        assert_eq!(ram.bytes[0x1c004..0x1c008], 255u32.to_le_bytes());
        assert_eq!(os.observations().len(), 1);
        // Draining empties the journal.
        assert!(os.observations().is_empty());
    }

    #[test]
    fn graceful_runs_answer_refusals_but_never_an_observed_scrd_request() {
        use super::observe;
        let mut os = SepOs::new(None).with_services(store(), true).unwrap();
        os.set_strict(false);
        map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
        let request = |service, tag| Frame {
            service,
            tag,
            opcode: 0,
            parameter: 0,
            data: 8,
        };
        for frame in [
            request(keystore::ID, 1),
            request(observe::CREDENTIALS_ID, 2),
        ] {
            assert!(reply(&mut os, frame).unwrap().is_empty());
        }
        let mut ram = crate::platform::dma::tests::Ram::new(0x10_0000, 0x1000);
        // Each DMA step consumes one request. The keystore refusal is
        // answered with its failure status; scrd is not answered at all.
        let (result, answer) = dma_step(&mut os, &mut ram);
        assert!(result.is_err());
        assert_eq!(answer, [keystore::failure(request(keystore::ID, 1))]);
        assert!(os.dma_pending());
        assert!(dma(&mut os, &mut ram).unwrap().is_empty());
        assert!(!os.dma_pending());
        let lines = os.observations();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("sks tag=1 op=0"), "{}", lines[0]);
        assert!(lines[0].ends_with("input=unregistered"), "{}", lines[0]);
        assert!(lines[1].starts_with("scrd tag=2 op=0"), "{}", lines[1]);
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
