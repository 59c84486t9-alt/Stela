//! The `dcpext` display coprocessor: the common ASC wrapper ([`super::asc`])
//! carrying an RTKit ([`super::rtkit`]) whose application endpoints are the
//! J473AP DCP's — the IOMFB link service (0x37) and the AFK/EPIC endpoints
//! (0x20 system, 0x24 DPAV, 0x2a DPTX port). The model terminates the
//! pipeline at the AP boundary: it answers the unchanged IOMobileFramebuffer
//! stack's calls and drives one fixed, connected SDR monitor, presenting
//! each submitted swap to a host [`scanout::Scanout`]. It never runs
//! `ipad14dcp` firmware.
//!
//! docs/research/display-gpu.md section 8 is the requirement matrix, each
//! row with its public source (Asahi Linux `drivers/gpu/drm/apple/`, m1n1
//! `proxyclient/m1n1/fw/dcp/` and `src/dcp/`) and status. The DCPEXT nub is
//! `quiesced` and `user-power-managed`, so (like the SMC) the coprocessor
//! acknowledges the AP's wake once RTKit enumeration completes behind the
//! boot-chain handoff.
//!
//! - [`link`] and [`rpc`]: the IOMFB link's wire format and the coprocessor
//!   end of its calls and callbacks through the AP's shared region, which the
//!   coprocessor masters through `dart-dcpext`.
//! - [`abi`]: the interface's tags, sizes and argument packing.
//! - [`iomfb`]: the methods, the published mode and hotplug, the swap queue
//!   and the completion callbacks.
//! - [`modes`]: the one advertised mode (EDID, IOAV timing and color records
//!   and their `TimingElements`/`ColorElements` properties).
//! - [`swap`]: `swap_submit_dcp`'s record and surfaces.
//! - [`afk`]: AFKEPV2 publication and command transport. Endpoint0x24
//!   publishes the real [`avipc`] controller for the connected monitor.
//!
//! Every call, callback, refusal and AFK message is recorded in a bounded
//! display [`Log`] the boot engine prints, so a boot shows what the guest
//! sent the model at the first named refusal.
pub mod abi;
pub mod afk;
pub mod avipc;
pub mod iomfb;
pub mod link;
pub mod modes;
pub mod rpc;
pub mod swap;

use super::asc::{Firmware, Message, TransitionRequest};
use super::rtkit::{Endpoint, RtKit};
use super::scanout::{Scanout, Surface};
use crate::Result;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::cell::RefCell;
use stela_contracts::dma::Port;
use stela_contracts::refuse;
use stela_formats::builds::Build;

/// The RTKit endpoint numbers the J473AP DCPEXT advertises to the AP. 0x37 is
/// the IOMFB link service (DCPEXTEndpoint24); the AFK/EPIC endpoints are the
/// system, DPAV and DPTX-port ones (m1n1 `src/dcp/system_ep.c`,
/// `dpav_ep.c`, `dptx_port_ep.c`).
pub const SYSTEM_ENDPOINT: u8 = 0x20;
pub const DPAV_ENDPOINT: u8 = 0x24;
pub const DPTX_ENDPOINT: u8 = 0x2a;
#[cfg(test)]
use super::scanout::Mode;
pub use link::IOMFB_ENDPOINT;

use stela_soc_data::dcp::ExternalIdentity;
const AFK_ENDPOINTS: [(u8, &str); 3] = [
    (SYSTEM_ENDPOINT, "system"),
    (DPAV_ENDPOINT, "DP AV"),
    (DPTX_ENDPOINT, "DPTX port"),
];

/// What the display model saw and did, in order, for the boot log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Log {
    /// The AP called `tag`; `input` is its leading bytes.
    Call {
        tag: [u8; 4],
        input: Vec<u8>,
        output: u32,
    },
    /// The coprocessor called the AP back.
    Callback {
        tag: [u8; 4],
        input: usize,
        output: u32,
    },
    /// The AP's output for a callback whose result the model uses.
    Answer { tag: [u8; 4], output: Vec<u8> },
    /// A whole call input kept for an unpinned layout.
    Payload { tag: [u8; 4], bytes: Vec<u8> },
    /// A swap's pixels reached the host scanout.
    Presented {
        swap_id: u32,
        /// The composed layers' surfaces, bottom to top.
        surfaces: Vec<Surface>,
    },
    /// Cumulative presentation progress in the bounded log.
    PresentSummary { total: u64, last_swap: u32 },
    /// A named refusal, with the call's interface row.
    Refused(String),
    /// A method of the interface with no model, answered with zeros.
    Unmodeled([u8; 4]),
    /// An AFK endpoint's message or ring entry.
    Afk {
        endpoint: u8,
        name: &'static str,
        event: afk::Event,
    },
    /// Entries dropped while the log was full.
    Dropped(u64),
}

/// A tag and its interface name.
struct Named<'a>(&'a [u8; 4]);

impl core::fmt::Display for Named<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = abi::method(self.0)
            .map(|row| row.name)
            .or_else(|| abi::callback(self.0).map(|row| row.name))
            .unwrap_or("");
        write!(f, "{} {name}", abi::tag_str(self.0))
    }
}

/// One or more lines, each starting `DCP `; a payload prints its nonzero
/// 32-byte rows with their offsets.
impl core::fmt::Display for Log {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Log::Call { tag, input, output } => {
                write!(f, "DCP call {} out={output:#x} in={input:02x?}", Named(tag))
            }
            Log::Callback { tag, input, output } => {
                write!(
                    f,
                    "DCP callback {} in={input:#x} out={output:#x}",
                    Named(tag)
                )
            }
            Log::Answer { tag, output } => write!(f, "DCP answer {} out={output:02x?}", Named(tag)),
            Log::Payload { tag, bytes } => {
                write!(f, "DCP payload {} bytes={:#x}", Named(tag), bytes.len())?;
                for (row, chunk) in bytes.chunks(32).enumerate() {
                    if chunk.iter().any(|&byte| byte != 0) {
                        write!(
                            f,
                            "\nDCP payload {} +{:#06x} {chunk:02x?}",
                            abi::tag_str(tag),
                            row * 32
                        )?;
                    }
                }
                Ok(())
            }
            Log::Presented { swap_id, surfaces } => {
                write!(f, "DCP presented swap {swap_id} surfaces={surfaces:x?}")
            }
            Log::PresentSummary { total, last_swap } => {
                write!(f, "DCP present summary total={total} last_swap={last_swap}")
            }
            Log::Refused(text) => write!(f, "DCP refused {text}"),
            Log::Unmodeled(tag) => {
                let name = abi::method(tag).map_or("", |row| row.name);
                write!(
                    f,
                    "DCP unmodeled {} {name}: answered with zeros",
                    abi::tag_str(tag)
                )
            }
            Log::Afk {
                endpoint,
                name,
                event: afk::Event::Received(word),
            } => write!(
                f,
                "DCP AFK ep={endpoint:#x} {name} type={:#x} word={word:#018x}",
                afk::kind(*word)
            ),
            Log::Afk {
                endpoint,
                name,
                event: afk::Event::Entry(entry),
            } => write!(f, "DCP AFK ep={endpoint:#x} {name} entry {entry:x?}"),
            Log::Afk {
                endpoint,
                name,
                event: afk::Event::Doorbell { tx, rx },
            } => write!(
                f,
                "DCP AFK ep={endpoint:#x} {name} doorbell tx={tx:x?} rx={rx:x?}"
            ),
            Log::Afk {
                endpoint,
                name,
                event: afk::Event::Lifecycle(packet),
            } => write!(
                f,
                "DCP AFK ep={endpoint:#x} {name} lifecycle packet={packet:02x?}"
            ),
            Log::Afk {
                endpoint,
                name,
                event:
                    afk::Event::Sent {
                        interface,
                        bytes,
                        packet_type,
                        category,
                        command_sequence,
                        status,
                    },
            } => write!(
                f,
                "DCP AFK ep={endpoint:#x} {name} sent interface={interface:#x} bytes={bytes:#x} type={packet_type:#x} category={category} command_sequence={command_sequence:x?} status={status:x?}"
            ),
            Log::Dropped(count) => write!(f, "DCP log dropped {count} entries"),
        }
    }
}

type Shared = Rc<RefCell<rpc::Link<iomfb::Methods>>>;

/// The IOMFB link-service endpoint: words in either direction pass through
/// the shared link, whose DMA step the coprocessor runs.
struct Iomfb(Shared);

impl Endpoint for Iomfb {
    fn check_reset(&self) -> Result<()> {
        let link = self.0.borrow();
        if !link.retained_idle() {
            return Err(refuse!(
                "DCP physical reset with unfinished RPC or scanout ownership"
            ));
        }
        link.service().check_reset()
    }
    fn reset(&mut self) -> Result<()> {
        self.check_reset()?;
        let mut link = self.0.borrow_mut();
        link.reset()?;
        link.service_mut().reset();
        Ok(())
    }
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<()> {
        outbox.push(self.0.borrow_mut().start()?);
        Ok(())
    }

    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<()> {
        self.0.borrow_mut().receive(payload);
        Ok(())
    }
}

/// An AFK endpoint: answered at once when no memory is needed, else at the
/// coprocessor's DMA step.
struct AfkEndpoint(Rc<RefCell<afk::Afk>>);

impl Endpoint for AfkEndpoint {
    fn check_reset(&self) -> Result<()> {
        self.0.borrow().check_reset()
    }
    fn reset(&mut self) -> Result<()> {
        self.0.borrow_mut().reset()
    }
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<()> {
        self.0.borrow_mut().start();
        Ok(())
    }

    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<()> {
        self.0.borrow_mut().receive(payload, outbox)
    }
}

/// A `dma::Port` as the link's bus.
struct PortBus<'p, 'a, 'b>(&'p mut Port<'a, 'b>);

impl rpc::Bus for PortBus<'_, '_, '_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<()> {
        self.0
            .read(address, buffer)
            .map_err(|_| refuse!("DCP shared-memory read faulted through dart-dcpext"))
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.0
            .write(address, data)
            .map_err(|_| refuse!("DCP shared-memory write faulted through dart-dcpext"))
    }
}

/// The DCPEXT coprocessor: RTKit with the DCP endpoints, the link's and the
/// AFK rings' DMA through `dart-dcpext`, and the surfaces' through the
/// display pipe's DART.
pub struct Coprocessor {
    rtkit: RtKit,
    link: Shared,
    afk: Vec<Rc<RefCell<afk::Afk>>>,
}

impl Coprocessor {
    /// A coprocessor presenting to `scanout`. `window` is `dart-dcpext`'s
    /// `vm-base` when the node is `truncate-dvas`: `AppleA7IOP::_restrictDVA`
    /// (kernel file 0x1bb1424) then hands the coprocessor only a DVA's low
    /// 32 bits, which lie in that window. `build` is the booted macOS build,
    /// whose link interface version the coprocessor speaks.
    #[cfg(test)]
    pub fn new(scanout: Box<dyn Scanout>, window: Option<u64>, build: &Build) -> Result<Self> {
        Self::for_external(scanout, window, ExternalIdentity::Unnumbered, build)
    }

    /// Bind a real scanout to one external pipe. Placement supplies the
    /// original pipe's identity and DMA streams; this constructor provides
    /// the complete existing monitor, controller, power and present services.
    pub fn for_external(
        scanout: Box<dyn Scanout>,
        window: Option<u64>,
        identity: ExternalIdentity,
        build: &Build,
    ) -> Result<Self> {
        Self::with_identity(iomfb::Methods::new(scanout), window, identity, build)
    }

    fn with_identity(
        methods: iomfb::Methods,
        window: Option<u64>,
        identity: ExternalIdentity,
        build: &Build,
    ) -> Result<Self> {
        let descriptor = avipc::descriptor(identity.interface_name()?);
        let display = methods.display_state();
        let link = Rc::new(RefCell::new(rpc::Link::new(
            methods,
            window,
            build.dcp_link_version,
        )));
        let afk: Vec<_> = AFK_ENDPOINTS
            .iter()
            .map(|&(endpoint, name)| Rc::new(RefCell::new(afk::Afk::new(endpoint, name, window))))
            .collect();
        afk.iter()
            .find(|afk| afk.borrow().endpoint == avipc::ENDPOINT)
            .ok_or(refuse!("DCPAVIPC controller transport is not provided"))?
            .borrow_mut()
            .register(descriptor, Box::new(avipc::Controller::new(display)))?;
        let mut endpoints: Vec<(u8, Box<dyn Endpoint>)> = afk
            .iter()
            .map(|afk| {
                let endpoint = afk.borrow().endpoint;
                (
                    endpoint,
                    Box::new(AfkEndpoint(afk.clone())) as Box<dyn Endpoint>,
                )
            })
            .collect();
        endpoints.push((IOMFB_ENDPOINT, Box::new(Iomfb(link.clone()))));
        let rtkit = RtKit::new(endpoints, build.rtkit_version)?;
        Ok(Self { rtkit, link, afk })
    }

    /// The coprocessor was used and quiesced by the boot chain.
    pub fn quiesced(mut self) -> Self {
        self.rtkit = self.rtkit.quiesced();
        self
    }

    /// The fixed mode the one connected display runs.
    #[cfg(test)]
    pub fn mode(&self) -> Mode {
        self.link.borrow().service().mode()
    }

    fn retained_idle(&self) -> bool {
        self.link.borrow().retained_idle()
            && !self.frame_pending()
            && self.afk.iter().all(|afk| afk.borrow().retained_idle())
    }

    /// Choose per-swap tracing or bounded presentation reports.
    pub fn set_swap_tracing(&mut self, enabled: bool) {
        self.link
            .borrow_mut()
            .service_mut()
            .set_swap_tracing(enabled);
    }

    /// The next display-log entry.
    pub fn take_log(&mut self) -> Option<Log> {
        if let Some(entry) = self.link.borrow_mut().service_mut().take_log() {
            return Some(entry);
        }
        self.afk.iter().find_map(|afk| {
            let mut afk = afk.borrow_mut();
            let event = afk.seen.pop_front()?;
            Some(Log::Afk {
                endpoint: afk.endpoint,
                name: afk.name,
                event,
            })
        })
    }

    /// Whether a submitted swap waits for its pixels.
    pub fn frame_pending(&self) -> bool {
        self.link.borrow().service().frame_pending()
    }

    /// Read the oldest submitted swap's surface through `port` (the display
    /// pipe's DART, where the AP mapped it), present it and queue the swap's
    /// completion callback, which leaves at the next link DMA step.
    pub fn present(&mut self, port: &mut Port<'_, '_>) -> Result<()> {
        let mut link = self.link.borrow_mut();
        link.service_mut()
            .present(|iova, bytes| port.read(iova, bytes).is_ok())
    }
}

impl Firmware for Coprocessor {
    fn check_reset(&self) -> Result<()> {
        self.rtkit.check_reset()
    }
    fn reset(&mut self) -> Result<()> {
        self.rtkit.reset()
    }
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        self.rtkit.start(outbox)
    }
    fn stop(&mut self) -> Result<()> {
        if !self.retained_idle() {
            return Err(refuse!(
                "DCP CPU stop with unfinished RPC, scanout or AFK work"
            ));
        }
        self.rtkit.stop()
    }
    fn resume(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        let previous = self.rtkit.iop_power();
        self.rtkit.resume(outbox)?;
        // Firmware 0x232fc restores the saved running state after its
        // hardware sleep primitive returns, invoking the same 8 -> 0x21
        // kept-link callback as an explicit IOP wake request.
        if matches!(previous, 0x201 | 0x202) {
            self.link.borrow_mut().service_mut().resume();
        }
        Ok(())
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<()> {
        if message.endpoint == 0 && message.payload >> 52 & 0xf == 6 {
            let fields = message.payload & !(0xf << 52);
            if fields == 0 {
                return Err(refuse!(
                    "DCP IOP memory-loss power transition is not modeled"
                ));
            }
            if matches!(fields, 0x201 | 0x202) && !self.retained_idle() {
                return Err(refuse!(
                    "DCP IOP sleep with unfinished RPC, scanout or AFK work"
                ));
            }
        }
        let previous = self.rtkit.iop_power();
        self.rtkit.receive(message, outbox)?;
        // Firmware 0x257f8 decodes wire 0x201/0x202 to internal state 8
        // and 0x220 to 0x21. Its kept-link power callback 0x187524
        // resumes only the 8 -> 0x21 edge, without a new endpoint Hello.
        if matches!(previous, 0x201 | 0x202) && self.rtkit.iop_power() == 0x220 {
            self.link.borrow_mut().service_mut().resume();
        }
        Ok(())
    }
    fn dma_pending(&self) -> bool {
        self.link.borrow().pending() || self.afk.iter().any(|afk| afk.borrow().pending())
    }
    fn dma(&mut self, port: &mut Port<'_, '_>, outbox: &mut Vec<Message>) -> Result<()> {
        let mut sent = Vec::new();
        for afk in &self.afk {
            let mut afk = afk.borrow_mut();
            let endpoint = afk.endpoint;
            let result = afk.dma(&mut PortBus(port), &mut sent);
            outbox.extend(sent.drain(..).map(|payload| Message { endpoint, payload }));
            result?;
        }
        let result = self.link.borrow_mut().dma(&mut PortBus(port), &mut sent);
        outbox.extend(sent.into_iter().map(|payload| Message {
            endpoint: IOMFB_ENDPOINT,
            payload,
        }));
        result
    }
    fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<()> {
        self.rtkit.poll(outbox)
    }
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        self.rtkit.take_transition()
    }
}

#[cfg(test)]
mod tests;
