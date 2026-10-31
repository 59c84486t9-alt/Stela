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
//! refused request gets the service protocol's failure answer, unless the
//! request may already have taken effect ([`super::transaction`]).
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
use crate::Result;
use alloc::{boxed::Box, collections::VecDeque, format, string::String, vec::Vec};
use stela_contracts::refuse;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

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
    /// traffic; `scrd` is then advertised and its requests never answered,
    /// so the kernel client takes its own timeout path and the run records
    /// the requests that follow: a diagnostic exception to the error-reply
    /// rule (docs/design/runtime.md "Unsupported operations").
    observe: Option<Journal>,
}

/// The native application services behind the catalog.
struct Services {
    xart: Xart,
    keystore: KeyStore,
    boot_policy: BootPolicy,
}

/// The SEP page that scales discovery capacities: 16 KiB, since
/// `AppleSEPManager::start` 0x2d67308 selects it from the SEP node's `aarch64`
/// property, which `stela_soc_data::board::sep_device` requires.
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
        }
    }

    /// The SEP's native services, advertised once OS active is reported:
    /// the xART pair over the anti-replay store `store`, the keystore and
    /// BootPolicy. With `observe`, their traffic is journaled and `scrd` is
    /// also advertised so its kernel client binds; its requests are
    /// recorded and never answered (a diagnostic mode: it checks nothing
    /// beyond its log). macOS LocalPolicies carry `kexts`.
    pub fn with_services(
        mut self,
        store: Nonces<Box<dyn Backend>>,
        observe: bool,
        kexts: Option<stela_formats::local_policy::Kexts>,
    ) -> Result<Self> {
        let mut services = xart::services().to_vec();
        services.extend([keystore::service(), boot_policy::service()]);
        if observe {
            services.extend(observe::services());
            self.observe = Some(Journal::default());
        }
        self.catalog = Catalog::new(services)?;
        let keystore = KeyStore::with_system_keys(store.system_key_root()?);
        self.services = Some(Services {
            xart: Xart::new(store),
            keystore,
            boot_policy: BootPolicy::new(kexts),
        });
        Ok(self)
    }

    /// Serve FileVault volume keys, with this start's inline wrapping key,
    /// drawn from `entropy`, in `engine`, which ANS shares.
    pub fn with_volume_keys(
        mut self,
        engine: crate::inline_key::Engine,
        entropy: &mut dyn super::Entropy,
    ) -> Result<Self> {
        if let Some(services) = self.services.as_mut() {
            let root = services.xart.store_mut().system_key_root()?;
            services.keystore =
                core::mem::take(&mut services.keystore).with_volume_keys(&root, engine, entropy)?;
        }
        Ok(self)
    }

    /// Record the booted sepOS's manifest hash for xART manifest commits.
    pub fn with_booted_manifest(mut self, manifest: Option<[u8; 48]>) -> Self {
        if let Some(services) = self.services.as_mut() {
            services.xart.set_booted_manifest(manifest);
        }
        self
    }

    /// Drain observed traffic and sanitized unsupported system-key metadata.
    /// The latter is available without enabling raw traffic observation.
    pub fn observations(&mut self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .observe
            .as_mut()
            .map(|journal| journal.drain().collect())
            .unwrap_or_default();
        if let Some(services) = self.services.as_mut() {
            lines.extend(services.keystore.diagnostics());
        }
        lines
    }

    /// The xART service state, when installed.
    #[cfg(test)]
    pub fn xart(&self) -> Option<&Xart> {
        self.services.as_ref().map(|services| &services.xart)
    }

    /// The keystore service state, when installed.
    #[cfg(test)]
    pub fn keystore(&self) -> Option<&KeyStore> {
        self.services.as_ref().map(|services| &services.keystore)
    }

    /// Whether application-service requests await the DMA step.
    pub fn dma_pending(&self) -> bool {
        self.pending_region.is_some() || !self.pending.is_empty()
    }

    /// Answer the queued application-service requests through `port`. A
    /// refusal or DMA fault returns its reason instead of the reply, after
    /// queueing its failure answer; an observed `scrd` request is recorded
    /// and gets none.
    pub fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<()> {
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
            return Ok(());
        }
        let services = self
            .services
            .as_mut()
            .ok_or(refuse!("SEP application service has no native handler"))?;
        let mut payload = Ool {
            buffers: self.buffers.iter().find(|b| b.service() == frame.service),
            port: &mut *port,
            read: 0,
        };
        let result = match frame.service {
            xart::MASTER_ID | xart::SLAVE_ID => services.xart.request(frame, &mut payload, entropy),
            keystore::ID => services.keystore.request(frame, &mut payload, entropy),
            boot_policy::ID => services
                .xart
                .policy_store_mut()
                .map_err(|reason| Refusal::answered(reason, boot_policy::not_supported(frame)))
                .and_then(|store| {
                    services
                        .boot_policy
                        .request(frame, &mut payload, store, entropy)
                }),
            _ => Err(Refusal::unanswerable(
                "SEP application service has no native handler",
            )),
        };
        let (answer, outcome) = match result {
            Ok(reply) => (Some(reply), Ok(())),
            Err(refusal) => {
                // The failure answer, once its bytes are written.
                let answer = refusal.answer.and_then(|answer| {
                    (answer.output.is_empty() || payload.output(&answer.output).is_ok())
                        .then_some(answer.frame)
                });
                (answer, Err(refusal.reason))
            }
        };
        if let Some(journal) = self.observe.as_mut()
            && let Some(name) = observe::name(frame.service)
        {
            journal.record(match answer {
                Some(reply) => format!(
                    "{name} tag={} answer op={} param={:#x} data={:#010x}",
                    reply.tag, reply.opcode, reply.parameter, reply.data
                ),
                None => format!("{name} tag={} unanswered", frame.tag),
            });
        }
        if let Some(reply) = answer {
            outbox.push(reply.mailbox());
        }
        outcome
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
    #[cfg(test)]
    pub fn with_catalog(mut self, catalog: Catalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// The shared-memory aggregate the AP mapped for the SEP, once received.
    #[cfg(test)]
    pub fn region(&self) -> Option<Region> {
        self.region
    }

    /// Directory metadata last validated through dart-sep. This makes no
    /// claim about an unrecovered channel's content or authentication.
    #[cfg(test)]
    pub fn layout(&self) -> Option<&Layout> {
        self.layout.as_ref()
    }

    /// Whether the SEP has reported its OS active to the control endpoint.
    #[cfg(any(test, feature = "test-support"))]
    pub fn os_active_sent(&self) -> bool {
        self.os_active_sent
    }
    #[cfg(test)]
    pub fn power(&self) -> Power {
        self.power
    }

    /// Whether the AP announced it is ready to sleep (`cmsgAP_SLEEP_READY`).
    #[cfg(test)]
    pub fn ap_sleep_ready(&self) -> bool {
        self.ap_sleep_ready
    }

    /// The OOL buffers an application service registered, if any.
    #[cfg(test)]
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
    ) -> Result<()> {
        match frame.service {
            message::BOOT => {
                if self.pending_region.is_some() || !self.pending.is_empty() {
                    return Err(refuse!("SEP shared-memory remap while DMA work is pending"));
                }
                let region = Region::from_message(frame.mailbox())?;
                self.pending_region = Some(region);
                Ok(())
            }
            message::CONTROL => self.control(frame, entropy, outbox),
            message::DISCOVERY => Err(refuse!(
                "SEP discovery is advertised by the SEP, not received from the AP"
            )),
            message::ROM => Err(refuse!(
                "SEPROM commands are not valid once sepOS is active"
            )),
            service if self.services.is_some() && self.catalog.service(service).is_ok() => {
                if !self.os_active_sent {
                    return Err(refuse!(
                        "SEP service request before sepOS reported OS active"
                    ));
                }
                if self.pending_region.is_some() {
                    return Err(refuse!(
                        "SEP service request while shared-memory remap is pending"
                    ));
                }
                if self.power != Power::Awake {
                    return Err(refuse!("SEP service request while the SEP sleeps or naps"));
                }
                if self.pending.len() == MAX_PENDING_REQUESTS {
                    return Err(refuse!(
                        "SEP application request queue exceeds the resource bound"
                    ));
                }
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.service == frame.service && pending.tag == frame.tag)
                {
                    return Err(refuse!(
                        "SEP application request repeats an outstanding service/tag"
                    ));
                }
                self.pending.push_back(frame);
                Ok(())
            }
            _ => Err(refuse!("SEP application service is not modeled")),
        }
    }

    fn control(
        &mut self,
        frame: Frame,
        entropy: &mut dyn Entropy,
        outbox: &mut Vec<Message>,
    ) -> Result<()> {
        if !self.os_active_sent {
            return Err(refuse!(
                "SEP control request before sepOS mapped its shared memory"
            ));
        }
        if self.pending_region.is_some() {
            return Err(refuse!(
                "SEP control request while shared-memory remap is pending"
            ));
        }
        let request = Request::decode(frame)?;
        if self.power != Power::Awake && !matches!(request, Request::Wake | Request::WakeFromNap) {
            return Err(refuse!("SEP control request while the SEP sleeps or naps"));
        }
        let data = match request {
            Request::Nop => Some(0),
            Request::Ool => {
                if self
                    .pending
                    .iter()
                    .any(|pending| pending.service == frame.parameter)
                {
                    return Err(refuse!(
                        "SEP OOL registration while its service has pending requests"
                    ));
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
                    return Err(refuse!(
                        "SEP OOL length is outside the service's advertised pages"
                    ));
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
                    return Err(refuse!(
                        "SEP sleep while application requests are pending is not modeled"
                    ));
                }
                self.power = Power::Asleep(kind);
                Some(0)
            }
            Request::Wake => {
                if !matches!(self.power, Power::Asleep(_)) {
                    return Err(refuse!("SEP wake without a preceding sleep"));
                }
                self.power = Power::Awake;
                self.ap_sleep_ready = false;
                Some(0)
            }
            Request::Nap => {
                if !self.pending.is_empty() {
                    return Err(refuse!(
                        "SEP nap while application requests are pending is not modeled"
                    ));
                }
                self.power = Power::Napping;
                None
            }
            Request::WakeFromNap => {
                if self.power != Power::Napping {
                    return Err(refuse!("SEP nap wake while the SEP is not napping"));
                }
                self.power = Power::Awake;
                outbox.push(control::notification(control::NAP_AWAKE, 0).mailbox());
                None
            }
            Request::NapOk => {
                return Err(refuse!("SEP nap acknowledgement without a SEP nap request"));
            }
            Request::ApSleepReady => {
                self.ap_sleep_ready = true;
                None
            }
            Request::SecurityMode => {
                let mode = self.security.ok_or(refuse!("SEP security mode is unknown: /chosen lacks the AP's effective production status and security mode"))?;
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
                    return Err(refuse!(
                        "SEP erase-install while application requests are pending is not modeled"
                    ));
                }
                self.services
                    .as_mut()
                    .ok_or(refuse!("SEP erase-install needs the xART store"))?
                    .xart
                    .store_mut()
                    .erase()?;
                Some(0)
            }
            Request::SelfTest => return Err(refuse!("SEP self test is not modeled")),
            Request::TtyIn(_) => return Err(refuse!("SEP console input is not modeled")),
            Request::RelayDma(_) => {
                return Err(refuse!(
                    "SEP relay DMA exists only on boards with pcie-up-interrupts"
                ));
            }
            Request::Panic => return Err(refuse!("the AP requested a SEP panic")),
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

fn dma_refusal(error: DmaError) -> stela_contracts::Refusal {
    match error {
        DmaError::Unsupported(reason) => reason,
        DmaError::Fault(code) => refuse!("SEP service OOL DMA fault in dart-sep", code),
        DmaError::Memory => refuse!("SEP service OOL buffer is outside guest RAM"),
    }
}

impl Payload for Ool<'_, '_, '_, '_> {
    fn input(&mut self, bytes: &mut [u8]) -> Result<()> {
        let buffers = self.buffers.ok_or(refuse!(
            "SEP service request before its OOL buffers are registered"
        ))?;
        buffers
            .read_input(self.port, self.read, bytes)
            .map_err(dma_refusal)?;
        self.read += bytes.len() as u64;
        Ok(())
    }

    fn output(&mut self, bytes: &[u8]) -> Result<()> {
        let buffers = self.buffers.ok_or(refuse!(
            "SEP service reply before its OOL buffers are registered"
        ))?;
        buffers
            .write_output(self.port, 0, bytes)
            .map_err(dma_refusal)
    }
}

#[cfg(test)]
mod tests;
