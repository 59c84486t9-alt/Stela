//! The `dcpext` display coprocessor: the common ASC wrapper ([`super::asc`])
//! carrying an RTKit ([`super::rtkit`]) whose application endpoints are the
//! J473AP DCP's — the IOMFB link service (0x37) and the AFK/EPIC endpoints
//! (0x20 system, 0x24 DPAV, 0x2a DPTX port). The model terminates the
//! pipeline at the AP boundary: it answers the unchanged IOMobileFramebuffer
//! stack's calls and drives one fixed, connected SDR monitor, presenting
//! each submitted swap to a host [`scanout::Scanout`]. It never runs
//! `ipad14dcp` firmware.
//!
//! The public sources are Asahi Linux `drivers/gpu/drm/apple/` and m1n1
//! `proxyclient/m1n1/fw/dcp/` and `src/dcp/`. The DCPEXT nub is
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
pub mod compose;
pub mod gpu;
pub mod iomfb;
pub mod link;
pub mod modes;
pub mod rpc;
pub mod swap;

use super::asc::{Firmware, Message, TransitionRequest};
use super::rtkit::{Endpoint, RtKit};
use super::scanout::{Rect, Scanout, Surface};
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
    /// The AP called `tag`, the interface's method `name`; `input` is its
    /// leading bytes.
    Call {
        tag: [u8; 4],
        name: &'static str,
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
    Payload {
        tag: [u8; 4],
        name: &'static str,
        bytes: Vec<u8>,
    },
    /// A swap the AP submitted: its enable mask and each layer's DVA, none
    /// where its surface pointer is null.
    Submitted {
        swap_id: u32,
        enabled: u32,
        /// The layers still waiting for their surface's GPU fence.
        fenced: u32,
        layers: [Option<u64>; swap::LAYERS],
    },
    /// A swap's pixels reached the host scanout.
    Presented {
        swap_id: u32,
        /// The composed layers' surfaces, bottom to top.
        surfaces: Vec<Surface>,
    },
    /// A swap latched at a vblank with a newer one, `shown`, presented in
    /// its place; `displayed` is what its completion tells the AP.
    Merged {
        swap_id: u32,
        shown: u32,
        displayed: bool,
    },
    /// A swap set layer `layer` to a surface of `surface` (width, height)
    /// shown from `source` into `destination` on the screen, a shape the
    /// slot did not have before: the first ones, whatever the tracing.
    Placement {
        swap_id: u32,
        layer: usize,
        surface: (u32, u32),
        source: Rect,
        destination: Rect,
    },
    /// Cumulative presentation progress in the bounded log.
    PresentSummary { total: u64, last_swap: u32 },
    /// How swaps reached the scanout over a window of the counter.
    Pacing(iomfb::Pacing),
    /// A named refusal, with the call's interface row.
    Refused(String),
    /// A swap shown before `io_fence_notify` named every surface it waited
    /// for: those layers may still have been drawing.
    FenceTimeout {
        swap_id: u32,
        fenced: u32,
        seconds: u64,
    },
    /// A method of the interface the model does not serve in full, its name,
    /// how it was answered and the parameter it was reported for, if any.
    Unmodeled {
        tag: [u8; 4],
        name: &'static str,
        answer: iomfb::Degraded,
        detail: Option<u32>,
    },
    /// An AFK endpoint's message or ring entry.
    Afk {
        endpoint: u8,
        name: &'static str,
        event: afk::Event,
    },
    /// Entries dropped while the log was full.
    Dropped(u64),
}

/// A callback tag and its name, which every interface shares.
struct Named<'a>(&'a [u8; 4]);

impl core::fmt::Display for Named<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = abi::callback(self.0).map_or("", |row| row.name);
        write!(f, "{} {name}", abi::tag_str(self.0))
    }
}

/// One or more lines, each starting `DCP `; a payload prints its nonzero
/// 32-byte rows with their offsets.
impl core::fmt::Display for Log {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Log::Call {
                tag,
                name,
                input,
                output,
            } => {
                write!(
                    f,
                    "DCP call {} {name} out={output:#x} in={input:02x?}",
                    abi::tag_str(tag)
                )
            }
            Log::Callback { tag, input, output } => {
                write!(
                    f,
                    "DCP callback {} in={input:#x} out={output:#x}",
                    Named(tag)
                )
            }
            Log::Answer { tag, output } => write!(f, "DCP answer {} out={output:02x?}", Named(tag)),
            Log::Payload { tag, name, bytes } => {
                write!(
                    f,
                    "DCP payload {} {name} bytes={:#x}",
                    abi::tag_str(tag),
                    bytes.len()
                )?;
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
            Log::Submitted {
                swap_id,
                enabled,
                fenced,
                layers,
            } => {
                write!(
                    f,
                    "DCP submitted swap {swap_id} enabled={enabled:#x} fenced={fenced:#x} layers={layers:x?}"
                )
            }
            Log::Presented { swap_id, surfaces } => {
                write!(f, "DCP presented swap {swap_id} surfaces={surfaces:x?}")
            }
            Log::Merged {
                swap_id,
                shown,
                displayed,
            } => write!(
                f,
                "DCP merged swap {swap_id} into swap {shown} displayed={}",
                u8::from(*displayed)
            ),
            Log::Placement {
                swap_id,
                layer,
                surface,
                source,
                destination,
            } => write!(
                f,
                "DCP LAYER swap {swap_id} layer {layer} surface={}x{} \
                 source={},{}+{}x{} destination={},{}+{}x{}",
                surface.0,
                surface.1,
                source.x,
                source.y,
                source.width,
                source.height,
                destination.x,
                destination.y,
                destination.width,
                destination.height
            ),
            Log::PresentSummary { total, last_swap } => {
                write!(f, "DCP present summary total={total} last_swap={last_swap}")
            }
            Log::Pacing(pacing) => write!(f, "{pacing}"),
            Log::Refused(text) => write!(f, "DCP refused {text}"),
            Log::FenceTimeout {
                swap_id,
                fenced,
                seconds,
            } => write!(
                f,
                "DCP showed swap {swap_id} with layers {fenced:#x} still fenced after {seconds} s: the AP never named their surfaces in io_fence_notify (reported once)"
            ),
            Log::Unmodeled {
                tag,
                name,
                answer,
                detail,
            } => {
                write!(f, "DCP unmodeled {} {name}", abi::tag_str(tag))?;
                if let Some(detail) = detail {
                    write!(f, " ({detail:#x})")?;
                }
                write!(f, ": {answer}")
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
        let interface = abi::interface(build.dcp_link_version)?;
        Self::with_identity(
            iomfb::Methods::new(scanout, interface),
            window,
            identity,
            build,
        )
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

    /// Advance the display to counter `now`: a queued scanout flush, and the
    /// vblank it passed, which opens a latch and queues the vsync.
    pub fn refresh(&mut self, now: u64) {
        self.link.borrow_mut().service_mut().refresh(now);
    }

    /// When the display next needs a look: its next vblank, while anyone
    /// listens for it, a swap waits or the scanout queued work.
    pub fn refresh_deadline(&self) -> Option<u64> {
        self.link.borrow().service().refresh_deadline()
    }

    /// Whether a compose runs, whose present a transfer finishes.
    pub fn composing(&self) -> bool {
        self.link.borrow().service().composing()
    }

    /// Whether a submitted swap waits for its pixels.
    pub fn frame_pending(&self) -> bool {
        self.link.borrow().service().frame_pending()
    }

    /// Whether the last vblank latches a swap at counter `now`, the oldest
    /// waiting one's surfaces' GPU fences having signaled.
    pub fn frame_ready(&mut self, now: u64) -> bool {
        self.link.borrow_mut().service_mut().frame_ready(now)
    }

    /// Present at counter `now` the swaps the last vblank latched, reading
    /// the newest one's surfaces through `port` (the display pipe's DART,
    /// where the AP mapped them), and queue their completion callbacks,
    /// which leave at the next link DMA step.
    /// [`Self::present`] composed outside the devices' lock
    /// ([`compose`]): the compose to run, its pages resolved through
    /// `resolve` in pages of `page` bytes, or `None` to present in place.
    pub fn compose(
        &mut self,
        now: u64,
        page: u64,
        resolve: impl FnMut(u64) -> core::result::Result<u64, stela_contracts::dma::DmaError>,
    ) -> Option<compose::Compose> {
        self.link
            .borrow_mut()
            .service_mut()
            .compose(now, page, resolve)
    }

    /// Finish the present a compose left once it ended
    /// ([`iomfb::Methods::finish_compose`]).
    pub fn finish_compose(&mut self) -> Result<bool> {
        self.link.borrow_mut().service_mut().finish_compose(0)
    }

    pub fn present(&mut self, now: u64, port: &mut Port<'_, '_>) -> Result<()> {
        let mut link = self.link.borrow_mut();
        link.service_mut()
            .present(now, |iova, bytes| port.read(iova, bytes).is_ok())
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
        // A compose still in flight keeps its swaps: the check below refuses.
        let _ = self.link.borrow_mut().service_mut().settle_compose();
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
            if matches!(fields, 0x201 | 0x202) {
                // As in `stop`: the idle check refuses one still in flight.
                let _ = self.link.borrow_mut().service_mut().settle_compose();
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
        // The calls, notices and answers this transfer carries happen now.
        let now = port.access.now;
        self.link.borrow_mut().service_mut().observe(now);
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
    fn take_unmodeled(&mut self) -> Vec<String> {
        self.link.borrow_mut().service_mut().take_unmodeled()
    }
}

#[cfg(test)]
mod tests;
