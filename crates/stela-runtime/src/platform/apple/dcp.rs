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
use crate::platform::dma::Port;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::cell::RefCell;

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

/// Identity of the one backed external output. The unnumbered DCPEXT and
/// numbered DCPEXT0/1 use the same original firmware protocol, but publish
/// distinct AFKEPV2 interface names. This does not model an internal panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExternalIdentity {
    #[default]
    Unnumbered,
    /// The external pipe ordinal, not the AFKEPV2 interface ID or unit.
    Numbered(u8),
}

impl ExternalIdentity {
    fn interface_name(self) -> Result<alloc::string::String, &'static str> {
        // t600xdcp_restore 0xf9434..0xf944c formats %s%c:%s:%u. Its external
        // instance byte 0 yields E; 1..10 yield 0..9. Each model has one
        // controller (unit 0) and an independently allocated interface ID.
        let suffix = match self {
            Self::Unnumbered => 'E',
            Self::Numbered(index @ 0..=9) => char::from(b'0' + index),
            Self::Numbered(_) => {
                return Err(
                    "DCP external pipe ordinal exceeds the native single-character identity",
                );
            }
        };
        Ok(alloc::format!("dispext{suffix}:{}:0", avipc::SERVICE_NAME))
    }
}

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
    /// A named refusal, with the call's interface row.
    Refused(String),
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
            Log::Refused(text) => write!(f, "DCP refused {text}"),
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
    fn check_reset(&self) -> Result<(), &'static str> {
        let link = self.0.borrow();
        if !link.retained_idle() {
            return Err("DCP physical reset with unfinished RPC or scanout ownership");
        }
        link.service().check_reset()
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.check_reset()?;
        let mut link = self.0.borrow_mut();
        link.reset()?;
        link.service_mut().reset();
        Ok(())
    }
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        outbox.push(self.0.borrow_mut().start()?);
        Ok(())
    }

    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.borrow_mut().receive(payload);
        Ok(())
    }
}

/// An AFK endpoint: answered at once when no memory is needed, else at the
/// coprocessor's DMA step.
struct AfkEndpoint(Rc<RefCell<afk::Afk>>);

impl Endpoint for AfkEndpoint {
    fn check_reset(&self) -> Result<(), &'static str> {
        self.0.borrow().check_reset()
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.0.borrow_mut().reset()
    }
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.borrow_mut().start();
        Ok(())
    }

    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.borrow_mut().receive(payload, outbox)
    }
}

/// A `dma::Port` as the link's bus.
struct PortBus<'p, 'a, 'b>(&'p mut Port<'a, 'b>);

impl rpc::Bus for PortBus<'_, '_, '_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        self.0
            .read(address, buffer)
            .map_err(|_| "DCP shared-memory read faulted through dart-dcpext")
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str> {
        self.0
            .write(address, data)
            .map_err(|_| "DCP shared-memory write faulted through dart-dcpext")
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
    /// 32 bits, which lie in that window.
    #[cfg(test)]
    pub fn new(scanout: Box<dyn Scanout>, window: Option<u64>) -> Result<Self, &'static str> {
        Self::for_external(scanout, window, ExternalIdentity::Unnumbered)
    }

    /// Bind a real scanout to one external pipe. Placement supplies the
    /// original pipe's identity and DMA streams; this constructor provides
    /// the complete existing monitor, controller, power and present services.
    pub fn for_external(
        scanout: Box<dyn Scanout>,
        window: Option<u64>,
        identity: ExternalIdentity,
    ) -> Result<Self, &'static str> {
        Self::with_identity(iomfb::Methods::new(scanout), window, identity)
    }

    fn with_identity(
        methods: iomfb::Methods,
        window: Option<u64>,
        identity: ExternalIdentity,
    ) -> Result<Self, &'static str> {
        let descriptor = avipc::descriptor(identity.interface_name()?);
        let display = methods.display_state();
        let link = Rc::new(RefCell::new(rpc::Link::new(methods, window)));
        let afk: Vec<_> = AFK_ENDPOINTS
            .iter()
            .map(|&(endpoint, name)| Rc::new(RefCell::new(afk::Afk::new(endpoint, name, window))))
            .collect();
        afk.iter()
            .find(|afk| afk.borrow().endpoint == avipc::ENDPOINT)
            .ok_or("DCPAVIPC controller transport is not provided")?
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
        let rtkit = RtKit::new(endpoints)?;
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
    pub fn present(&mut self, port: &mut Port<'_, '_>) -> Result<(), &'static str> {
        let mut link = self.link.borrow_mut();
        link.service_mut()
            .present(|iova, bytes| port.read(iova, bytes).is_ok())
    }
}

impl Firmware for Coprocessor {
    fn check_reset(&self) -> Result<(), &'static str> {
        self.rtkit.check_reset()
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.rtkit.reset()
    }
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.start(outbox)
    }
    fn stop(&mut self) -> Result<(), &'static str> {
        if !self.retained_idle() {
            return Err("DCP CPU stop with unfinished RPC, scanout or AFK work");
        }
        self.rtkit.stop()
    }
    fn resume(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        let previous = self.rtkit.iop_power();
        self.rtkit.resume(outbox)?;
        // Firmware 0x232fc restores the saved running state after its
        // hardware sleep primitive returns, invoking the same 8 -> 0x21
        // retained-link callback as an explicit IOP wake request.
        if matches!(previous, 0x201 | 0x202) {
            self.link.borrow_mut().service_mut().resume();
        }
        Ok(())
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if message.endpoint == 0 && message.payload >> 52 & 0xf == 6 {
            let fields = message.payload & !(0xf << 52);
            if fields == 0 {
                return Err("DCP IOP memory-loss power transition is not modeled");
            }
            if matches!(fields, 0x201 | 0x202) && !self.retained_idle() {
                return Err("DCP IOP sleep with unfinished RPC, scanout or AFK work");
            }
        }
        let previous = self.rtkit.iop_power();
        self.rtkit.receive(message, outbox)?;
        // Firmware 0x257f8 decodes wire 0x201/0x202 to internal state 8
        // and 0x220 to 0x21. Its retained-link power callback 0x187524
        // resumes only the 8 -> 0x21 edge, without a new endpoint Hello.
        if matches!(previous, 0x201 | 0x202) && self.rtkit.iop_power() == 0x220 {
            self.link.borrow_mut().service_mut().resume();
        }
        Ok(())
    }
    fn dma_pending(&self) -> bool {
        self.link.borrow().pending() || self.afk.iter().any(|afk| afk.borrow().pending())
    }
    fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
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
    fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.poll(outbox)
    }
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        self.rtkit.take_transition()
    }
}

#[cfg(test)]
mod tests {
    use super::super::scanout::PixelFormat;
    use super::*;
    use crate::platform::dma::{DmaError, tests::Ram};

    const RAM: u64 = 0x8_0000_0000;

    struct TestScreen(Mode, Rc<RefCell<usize>>);
    impl Scanout for TestScreen {
        fn mode(&self) -> Mode {
            self.0
        }
        fn present(&mut self, _rows: &[u8]) -> Result<(), &'static str> {
            *self.1.borrow_mut() += 1;
            Ok(())
        }
    }

    fn screen(width: u32, height: u32) -> (Box<dyn Scanout>, Rc<RefCell<usize>>) {
        let presented = Rc::new(RefCell::new(0));
        let mode = Mode {
            width,
            height,
            format: PixelFormat::Bgra8888,
        };
        (Box::new(TestScreen(mode, presented.clone())), presented)
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
            _: &mut super::super::bus::Access<'_>,
        ) -> Result<u64, DmaError> {
            Ok(iova)
        }
    }

    fn with_port<T>(ram: &mut Ram, run: impl FnOnce(&mut Port<'_, '_>) -> T) -> T {
        let mut latch = super::super::interrupt::InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Identity,
            stream: 5,
            memory: ram,
            access: &mut access,
        };
        run(&mut port)
    }

    fn dma(coprocessor: &mut Coprocessor, ram: &mut Ram) -> Result<Vec<Message>, &'static str> {
        with_port(ram, |port| {
            let mut outbox = Vec::new();
            coprocessor.dma(port, &mut outbox)?;
            Ok(outbox)
        })
    }

    /// Hello, the region at DVA 0x4000 (truncated) and ready.
    fn up(coprocessor: &mut Coprocessor, ram: &mut Ram) -> Iomfb {
        let mut endpoint = Iomfb(coprocessor.link.clone());
        let mut sent = Vec::new();
        endpoint.start(&mut sent).unwrap();
        assert_eq!(sent, [0x100 | 211 << 16]);
        ram.bytes[0x4000 + 12] = 4;
        endpoint
            .receive(link::Word::Region { dva: 0x4000 }.encode(), &mut sent)
            .unwrap();
        assert!(coprocessor.dma_pending());
        let ready = dma(coprocessor, ram).unwrap();
        assert_eq!(ready[0].endpoint, IOMFB_ENDPOINT);
        assert_eq!(ready[0].payload & 3, 1);
        endpoint
    }

    const AP1: link::Stream = link::Stream {
        owner: link::Owner::Ap,
        index: 1,
    };

    /// The AP writes a call on AP stream 1 at `offset` and sends it.
    fn call(
        endpoint: &mut Iomfb,
        ram: &mut Ram,
        offset: u16,
        tag: &[u8; 4],
        input: &[u8],
        output: u32,
        opens: bool,
    ) -> link::Rpc {
        let header = link::Header {
            tag: *tag,
            input: input.len() as u32,
            output,
        };
        let at = 0x4000 + AP1.calls() as usize + usize::from(offset);
        ram.bytes[at..at + 12].copy_from_slice(&header.bytes());
        ram.bytes[at + 12..at + 12 + input.len()].copy_from_slice(input);
        let rpc = link::Rpc {
            answer: false,
            stream: AP1,
            opens,
            offset,
            length: header.length().unwrap(),
            token: 0,
        };
        endpoint
            .receive(link::Word::Rpc(rpc).encode(), &mut Vec::new())
            .unwrap();
        rpc
    }

    #[test]
    fn physical_reset_refuses_accepted_work_then_releases_only_an_idle_session() {
        let (scanout, presented) = screen(1920, 1080);
        let mut coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        let mut endpoint = up(&mut coprocessor, &mut ram);
        let heap = coprocessor.link.borrow().heap();
        let request = call(&mut endpoint, &mut ram, 0, b"A451", &[], 4, true);
        assert!(coprocessor.check_reset().is_err());
        assert!(coprocessor.reset().is_err());
        assert_eq!(coprocessor.link.borrow().heap(), heap);
        let reply = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(reply[0].payload, link::Word::Rpc(request.answer()).encode());
        coprocessor.check_reset().unwrap();
        coprocessor.reset().unwrap();
        assert!(!coprocessor.link.borrow().is_up());
        assert_eq!(coprocessor.link.borrow().heap(), None);
        assert!(!coprocessor.dma_pending());
        assert_eq!(*presented.borrow(), 0);
        assert_eq!(coprocessor.mode().width, 1920);
        // Physical reset itself emits nothing. A separate CPU start begins
        // cold enumeration, preserving the implemented controller descriptor.
        let mut output = Vec::new();
        coprocessor.start(&mut output).unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].payload >> 52, 1);
        let mut endpoint = up(&mut coprocessor, &mut ram);
        call(&mut endpoint, &mut ram, 0, b"A451", &[], 4, true);
        assert_eq!(dma(&mut coprocessor, &mut ram).unwrap().len(), 1);
    }

    #[test]
    fn the_link_comes_up_and_answers_through_the_coprocessors_dart() {
        let (scanout, _) = screen(1920, 1080);
        let mut coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        let mut endpoint = up(&mut coprocessor, &mut ram);
        let a451 = call(&mut endpoint, &mut ram, 0, b"A451", &[], 4, true);
        let answer = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(answer[0].payload, link::Word::Rpc(a451.answer()).encode());
        let at = 0x4000 + 0x8000;
        assert_eq!(&ram.bytes[at + 12..at + 16], &1920u32.to_le_bytes());
        assert!(!coprocessor.dma_pending());
        assert!(matches!(coprocessor.take_log(), Some(Log::Call { tag, .. }) if &tag == b"A451"));
    }

    fn iop_power(coprocessor: &mut Coprocessor, state: u64) -> Result<Vec<Message>, &'static str> {
        let mut out = Vec::new();
        coprocessor.receive(
            Message {
                endpoint: 0,
                payload: 6 << 52 | state,
            },
            &mut out,
        )?;
        Ok(out)
    }

    fn quiesced(link: &Shared) -> bool {
        rpc::Service::call(link.borrow_mut().service_mut(), *b"A035", &[], 4).is_err()
    }

    #[test]
    fn iop_sleep_to_wake_resumes_the_retained_rpc_region_without_a_hello() {
        for sleep in [0x201, 0x202] {
            let (scanout, _) = screen(1920, 1080);
            let mut coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
            let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
            let mut endpoint = up(&mut coprocessor, &mut ram);
            // Bring a separate AFK transport up before the display sleeps.
            // Retained power must not restart it or clear its registered rings.
            let afk = coprocessor.afk[0].clone();
            afk.borrow_mut()
                .receive(afk::INIT << 48 | 0x100, &mut Vec::new())
                .unwrap();
            afk.borrow_mut()
                .receive(afk::GETBUF_ACK << 48 | 0x8000, &mut Vec::new())
                .unwrap();
            dma(&mut coprocessor, &mut ram).unwrap();
            afk.borrow_mut()
                .receive(afk::START << 48, &mut Vec::new())
                .unwrap();
            assert!(afk.borrow().started());
            let heap = coprocessor.link.borrow().heap();
            let shutdown = call(
                &mut endpoint,
                &mut ram,
                0,
                b"A500",
                &[0, 0, 0xaa, 0xaa],
                0,
                true,
            );
            assert_eq!(
                dma(&mut coprocessor, &mut ram).unwrap()[0].payload,
                link::Word::Rpc(shutdown.answer()).encode()
            );
            assert!(quiesced(&coprocessor.link));
            // A wake request without a preceding sleep does not revive A500.
            iop_power(&mut coprocessor, 0x220).unwrap();
            assert!(quiesced(&coprocessor.link));
            iop_power(&mut coprocessor, sleep).unwrap();
            assert!(iop_power(&mut coprocessor, 0x221).is_err());
            assert_eq!(coprocessor.rtkit.iop_power(), sleep);
            assert!(quiesced(&coprocessor.link));
            let out = iop_power(&mut coprocessor, 0x220).unwrap();
            // Only RTKit's power ACK: no Hello, new region or endpoint reset.
            assert_eq!(
                out,
                [Message {
                    endpoint: 0,
                    payload: 7 << 52 | 0x220
                }]
            );
            assert!(coprocessor.link.borrow().is_up());
            assert!(afk.borrow().started());
            assert_eq!(coprocessor.link.borrow().heap(), heap);
            assert!(!coprocessor.dma_pending());
            let request = call(&mut endpoint, &mut ram, 0, b"A451", &[], 4, true);
            let answer = dma(&mut coprocessor, &mut ram).unwrap();
            assert_eq!(
                answer[0].payload,
                link::Word::Rpc(request.answer()).encode()
            );
            assert_eq!(&ram.bytes[0xc00c..0xc010], &1920u32.to_le_bytes());
            assert_eq!(coprocessor.link.borrow().heap(), heap);
            // Repeated wake and a rail-off-to-wake request are distinct from
            // the retained sleep edge and leave a new shutdown quiesced.
            call(
                &mut endpoint,
                &mut ram,
                0,
                b"A500",
                &[0, 0, 0xaa, 0xaa],
                0,
                true,
            );
            dma(&mut coprocessor, &mut ram).unwrap();
            iop_power(&mut coprocessor, 0x220).unwrap();
            assert!(quiesced(&coprocessor.link));
            assert_eq!(
                iop_power(&mut coprocessor, 0),
                Err("DCP IOP memory-loss power transition is not modeled")
            );
            iop_power(&mut coprocessor, 0x220).unwrap();
            assert!(quiesced(&coprocessor.link));
        }
    }

    #[test]
    fn asc_cpu_halt_and_restart_resume_the_retained_dcp_link_without_an_iop_request() {
        use super::super::asc::{Asc, Lines};
        use super::super::bus::{Access, MmioDevice, Width};
        use super::super::interrupt::InterruptLatch;

        fn send(asc: &mut Asc, access: &mut Access<'_>, endpoint: u8, payload: u64) {
            asc.write(0x8800, Width::Double, payload, access).unwrap();
            asc.write(0x8808, Width::Double, u64::from(endpoint), access)
                .unwrap();
        }
        fn take(asc: &mut Asc, access: &mut Access<'_>) -> u64 {
            let payload = asc.read(0x8830, Width::Double, access).unwrap();
            asc.read(0x8838, Width::Double, access).unwrap();
            payload
        }

        let (scanout, _) = screen(1920, 1080);
        let coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
        let mut asc = Asc::booted(Box::new(coprocessor), Lines::default()).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(take(&mut asc, &mut access) >> 52, 1); // RTKit Hello.
        send(&mut asc, &mut access, 0, 2 << 52 | 12 | 12 << 16);
        assert_eq!(take(&mut asc, &mut access) >> 52, 8);
        send(&mut asc, &mut access, 0, 8 << 52 | 1);
        assert_eq!(take(&mut asc, &mut access) >> 52, 8);
        send(&mut asc, &mut access, 0, 8 << 52 | 1 << 51 | 1 << 32);
        assert_eq!(take(&mut asc, &mut access), 7 << 52 | 0x20);
        send(
            &mut asc,
            &mut access,
            0,
            5 << 52 | u64::from(IOMFB_ENDPOINT) << 32 | 2,
        );
        assert_eq!(take(&mut asc, &mut access), 0x100 | 211 << 16);
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        ram.bytes[0x4000 + 12] = 4;
        send(
            &mut asc,
            &mut access,
            IOMFB_ENDPOINT,
            link::Word::Region { dva: 0x4000 }.encode(),
        );
        with_port(&mut ram, |port| asc.service_dma(port)).unwrap();
        take(&mut asc, &mut access);
        let shared = asc.firmware::<Coprocessor>().unwrap().link.clone();
        let heap = shared.borrow().heap();
        let mut endpoint = Iomfb(shared.clone());
        call(
            &mut endpoint,
            &mut ram,
            0,
            b"A500",
            &[0, 0, 0xaa, 0xaa],
            0,
            true,
        );
        // A CPU stop cannot abandon a queued DMA/RPC message.
        assert!(asc.write(0x44, Width::Word, 0, &mut access).is_err());
        asc.write(0x8800, Width::Double, 6 << 52 | 0x201, &mut access)
            .unwrap();
        assert!(asc.write(0x8808, Width::Double, 0, &mut access).is_err());
        assert_eq!(
            asc.firmware::<Coprocessor>().unwrap().rtkit.iop_power(),
            0x20
        );
        assert!(asc.read(0x8830, Width::Double, &mut access).is_err());
        with_port(&mut ram, |port| asc.service_dma(port)).unwrap();
        take(&mut asc, &mut access);
        send(&mut asc, &mut access, 0, 6 << 52 | 0x201);
        assert_eq!(take(&mut asc, &mut access), 7 << 52 | 0x201);
        asc.write(0x8114, Width::Word, 0, &mut access).unwrap();
        asc.write(0x44, Width::Word, 0, &mut access).unwrap();
        assert_eq!(asc.read(0x44, Width::Word, &mut access), Ok(0));
        assert!(!asc.dma_pending());
        assert!(with_port(&mut ram, |port| asc.service_dma(port)).is_err());
        asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
        // The running notification waits behind I2A delivery, preserving the
        // AP's ordering. Repeated RUN is a no-op, not another wake or Hello.
        assert!(!quiesced(&shared));
        assert!(asc.read(0x8830, Width::Double, &mut access).is_err());
        asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
        asc.write(0x8114, Width::Word, 1, &mut access).unwrap();
        assert_eq!(take(&mut asc, &mut access), 7 << 52 | 0x20);
        assert!(asc.read(0x8830, Width::Double, &mut access).is_err());
        assert_eq!(shared.borrow().heap(), heap);
        let request = call(&mut endpoint, &mut ram, 0, b"A451", &[], 4, true);
        with_port(&mut ram, |port| asc.service_dma(port)).unwrap();
        assert_eq!(
            take(&mut asc, &mut access),
            link::Word::Rpc(request.answer()).encode()
        );
        assert_eq!(&ram.bytes[0xc00c..0xc010], &1920u32.to_le_bytes());
    }

    #[test]
    fn start_signal_nests_start_hardware_boot_through_the_coprocessor() {
        // hello -> region -> ready -> A401 start_signal, which the
        // coprocessor answers by nesting D120 start_hardware_boot, inside
        // which the AP nests A451; the AP answers D120 so A401 returns.
        let (scanout, _) = screen(1920, 1080);
        let mut coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        let mut endpoint = up(&mut coprocessor, &mut ram);
        let a401 = call(&mut endpoint, &mut ram, 0, b"A401", &[], 4, true);
        let a401_at = 0x4000 + AP1.calls() as usize;
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        let d120 = match link::Word::decode(out[0].payload).unwrap() {
            link::Word::Rpc(rpc) => rpc,
            other => panic!("expected the D120 callback, got {other:?}"),
        };
        assert!(!d120.answer && !d120.opens && d120.stream == AP1);
        let d120_at = 0x4000 + AP1.nested() as usize + d120.offset as usize;
        assert_eq!(
            &link::Header::parse(ram.bytes[d120_at..d120_at + 12].try_into().unwrap()).tag,
            b"D120"
        );
        let a451 = call(&mut endpoint, &mut ram, 0x40, b"A451", &[], 4, false);
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(out[0].payload, link::Word::Rpc(a451.answer()).encode());
        ram.bytes[d120_at + 12..d120_at + 16].copy_from_slice(&1u32.to_le_bytes());
        endpoint
            .receive(link::Word::Rpc(d120.answer()).encode(), &mut Vec::new())
            .unwrap();
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        let a401_answer = match link::Word::decode(out[0].payload).unwrap() {
            link::Word::Rpc(rpc) => rpc,
            other => panic!("expected the A401 answer, got {other:?}"),
        };
        assert_eq!(a401_answer, a401.answer());
        assert_eq!(&ram.bytes[a401_at + 12..a401_at + 16], &1u32.to_le_bytes());
        assert!(!coprocessor.dma_pending());
    }

    const AV_BUFFER: usize = 0x4000 + link::REGION_BYTES as usize + 0x4000;

    fn word(ram: &Ram, at: usize) -> u32 {
        u32::from_le_bytes(ram.bytes[at..at + 4].try_into().unwrap())
    }

    fn take_controller_packet(ram: &mut Ram) -> Option<Vec<u8>> {
        let ring = AV_BUFFER + 0x2000;
        let read = word(ram, ring + 0x80) as usize;
        if read == word(ram, ring + 0x100) as usize {
            return None;
        }
        let at = ring + 0x180 + read;
        assert_eq!(word(ram, at), 0x2050_4f49);
        let length = word(ram, at + 4) as usize;
        let block = (length + 16).next_multiple_of(0x80);
        assert!(read + block <= 0x1e80); // Bounded fixture never wraps.
        assert_eq!(
            &ram.bytes[at + 18..at + 20],
            &avipc::INTERFACE.to_le_bytes()
        );
        let packet = ram.bytes[at + 24..at + 16 + length].to_vec();
        let next = if read + block == 0x1e80 {
            0
        } else {
            read + block
        };
        ram.bytes[ring + 0x80..ring + 0x84].copy_from_slice(&(next as u32).to_le_bytes());
        Some(packet)
    }

    fn controller_start(coprocessor: &mut Coprocessor, ram: &mut Ram) -> Vec<u8> {
        let transport = coprocessor
            .afk
            .iter()
            .find(|endpoint| endpoint.borrow().endpoint == avipc::ENDPOINT)
            .unwrap()
            .clone();
        transport.borrow_mut().start();
        transport
            .borrow_mut()
            .receive(afk::INIT << 48 | 0x100, &mut Vec::new())
            .unwrap();
        transport
            .borrow_mut()
            .receive(afk::GETBUF_ACK << 48 | AV_BUFFER as u64, &mut Vec::new())
            .unwrap();
        dma(coprocessor, ram).unwrap();
        transport
            .borrow_mut()
            .receive(afk::START << 48, &mut Vec::new())
            .unwrap();
        dma(coprocessor, ram).unwrap();
        take_controller_packet(ram).expect("controller publication")
    }

    fn controller_exchange(
        coprocessor: &mut Coprocessor,
        ram: &mut Ram,
        logical: &[u8],
    ) -> Option<Vec<u8>> {
        let read = word(ram, AV_BUFFER + 0x100) as usize;
        let size = logical.len() + 8;
        let block = (size + 16).next_multiple_of(0x80);
        assert!(read + block < 0x1e80);
        let mut entry = alloc::vec![0; block];
        entry[..4].copy_from_slice(&0x2050_4f49u32.to_le_bytes());
        entry[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        entry[18..20].copy_from_slice(&avipc::INTERFACE.to_le_bytes());
        entry[20..24].copy_from_slice(&(logical.len() as u32).to_le_bytes());
        entry[24..24 + logical.len()].copy_from_slice(logical);
        let at = AV_BUFFER + 0x180 + read;
        ram.bytes[at..at + block].copy_from_slice(&entry);
        ram.bytes[AV_BUFFER + 0x100..AV_BUFFER + 0x104]
            .copy_from_slice(&((read + block) as u32).to_le_bytes());
        let transport = coprocessor
            .afk
            .iter()
            .find(|endpoint| endpoint.borrow().endpoint == avipc::ENDPOINT)
            .unwrap()
            .clone();
        transport
            .borrow_mut()
            .receive(afk::RECV << 48, &mut Vec::new())
            .unwrap();
        dma(coprocessor, ram).unwrap();
        take_controller_packet(ram)
    }

    fn controller_call(
        coprocessor: &mut Coprocessor,
        ram: &mut Ram,
        command: u32,
        value: Option<u64>,
    ) -> Vec<u8> {
        let size: usize = if value.is_some() { 0x20 } else { 0x10 };
        let mut packet = alloc::vec![0; 24 + 0x40 + size];
        packet[8] = 0xc0;
        packet[9] = 1;
        packet[17] = command as u8 + 0x70;
        packet[20..24].copy_from_slice(&0x100u32.to_le_bytes());
        packet[28..32].copy_from_slice(&command.to_le_bytes());
        packet[32..36].copy_from_slice(&(size as u32).to_le_bytes());
        packet[36..40].copy_from_slice(&0x6970_6378u32.to_le_bytes());
        if let Some(value) = value {
            packet[24 + 0x50..24 + 0x58].copy_from_slice(&value.to_le_bytes());
        }
        let reply = controller_exchange(coprocessor, ram, &packet).expect("controller reply");
        assert_eq!(&reply[8..10], &[0xc0, 2]);
        assert_eq!(reply[17], packet[17]);
        assert_eq!(&reply[20..24], &[0; 4]);
        assert_eq!(&reply[24..24 + 0x40], &packet[24..24 + 0x40]);
        reply[24..].to_vec()
    }

    #[test]
    fn the_published_controller_owns_real_commands_shared_power_and_transport_lifetime() {
        for (identity, name) in [
            (
                ExternalIdentity::Unnumbered,
                "dispextE:dcpav-controller-epic:0",
            ),
            (
                ExternalIdentity::Numbered(0),
                "dispext0:dcpav-controller-epic:0",
            ),
            (
                ExternalIdentity::Numbered(1),
                "dispext1:dcpav-controller-epic:0",
            ),
        ] {
            check_published_controller(identity, name);
        }
    }

    fn check_published_controller(identity: ExternalIdentity, name: &str) {
        let (scanout, _) = screen(4, 2);
        let mut coprocessor = Coprocessor::for_external(scanout, Some(RAM), identity).unwrap();
        let mut ram = Ram::new(RAM, AV_BUFFER + 0x4000);
        let published = controller_start(&mut coprocessor, &mut ram);
        assert_eq!(&published[8..11], &[0x11, 0, 1]);
        assert_eq!(&published[16..47], &name.as_bytes()[..31]);
        assert_eq!(published[47], 0);
        let properties = core::str::from_utf8(&published[48..published.len() - 1]).unwrap();
        assert_eq!(published.last(), Some(&0));
        for expected in [
            "<key>EPICName</key><string>dcpav-controller-epic</string>",
            "<key>EPICLocation</key><string>External</string>",
            "<key>EPICUnit</key><integer size=\"32\">0</integer>",
            "<key>EPICProviderClass</key><string>AppleDCPDPTXController</string>",
            &alloc::format!("<string>{name}</string>"),
            "<key>interface-id</key><integer size=\"32\">1</integer>",
        ] {
            assert!(properties.contains(expected));
        }
        assert!(!properties.contains("RequiresCommandDelegate"));
        let mut open = alloc::vec![0; 16];
        open[8] = 0x12;
        open[10] = 1;
        assert!(controller_exchange(&mut coprocessor, &mut ram, &open).is_none());
        for (command, expected) in [(12, 1u64), (13, 1), (14, 0), (4, 1)] {
            let reply = controller_call(&mut coprocessor, &mut ram, command, Some(0));
            assert_eq!(&reply[0x40..0x44], &[0; 4]);
            assert_eq!(&reply[0x50..0x58], &expected.to_le_bytes());
        }
        controller_call(&mut coprocessor, &mut ram, 6, Some(0));
        assert_eq!(coprocessor.link.borrow().service().powered(), Some(false));
        // The same fixed monitor state is reached through ordinary IOMFB RPC.
        let mut endpoint = up(&mut coprocessor, &mut ram);
        let mut power = [0; 0x10];
        power[..8].copy_from_slice(&1u64.to_le_bytes());
        call(&mut endpoint, &mut ram, 0, b"A484", &power, 8, true);
        dma(&mut coprocessor, &mut ram).unwrap();
        let reply = controller_call(&mut coprocessor, &mut ram, 7, Some(0));
        assert_eq!(&reply[0x50..0x58], &1u64.to_le_bytes());
        controller_call(&mut coprocessor, &mut ram, 6, Some(0));
        assert_eq!(
            iop_power(&mut coprocessor, 0x201).unwrap()[0].payload,
            7 << 52 | 0x201
        );
        assert_eq!(
            iop_power(&mut coprocessor, 0x220).unwrap()[0].payload,
            7 << 52 | 0x220
        );
        let reply = controller_call(&mut coprocessor, &mut ram, 7, Some(0));
        assert_eq!(&reply[0x50..0x58], &[0; 8]); // Retained IOP wake preserves the monitor.
        controller_call(&mut coprocessor, &mut ram, 5, None);
        open[8] = 0x13;
        assert!(controller_exchange(&mut coprocessor, &mut ram, &open).is_none());
        let transport = coprocessor
            .afk
            .iter()
            .find(|ep| ep.borrow().endpoint == avipc::ENDPOINT)
            .unwrap()
            .clone();
        let mut sent = Vec::new();
        transport
            .borrow_mut()
            .receive(afk::SHUTDOWN << 48, &mut sent)
            .unwrap();
        assert_eq!(sent, [afk::SHUTDOWN_ACK << 48]);
        assert_eq!(controller_start(&mut coprocessor, &mut ram), published);
        let reply = controller_call(&mut coprocessor, &mut ram, 7, Some(0));
        assert_eq!(&reply[0x50..0x58], &[0; 8]); // Close/restart never invent power-on.
    }

    #[test]
    fn a_presented_swap_completes_on_a_coprocessor_stream() {
        for identity in [
            ExternalIdentity::Unnumbered,
            ExternalIdentity::Numbered(0),
            ExternalIdentity::Numbered(1),
        ] {
            check_presented_swap(identity);
        }
    }

    #[test]
    fn an_unrepresentable_external_identity_refuses_before_publication() {
        let (scanout, _) = screen(4, 2);
        assert!(matches!(
            Coprocessor::for_external(scanout, None, ExternalIdentity::Numbered(10)),
            Err("DCP external pipe ordinal exceeds the native single-character identity")
        ));
    }

    fn check_presented_swap(identity: ExternalIdentity) {
        let (scanout, presented) = screen(4, 2);
        let mut coprocessor = Coprocessor::for_external(scanout, Some(RAM), identity).unwrap();
        let mut ram = Ram::new(RAM, AV_BUFFER + 0x4000);
        controller_start(&mut coprocessor, &mut ram);
        let mut endpoint = up(&mut coprocessor, &mut ram);
        let start = abi::Packed::new()
            .u32(0)
            .u64(0)
            .bool(false)
            .finish(0x10)
            .unwrap();
        call(&mut endpoint, &mut ram, 0, b"A406", &start, 8, true);
        dma(&mut coprocessor, &mut ram).unwrap();
        // One 4x2 BGRA layer after the link's region.
        let surface = RAM + 0x4000 + link::REGION_BYTES;
        let submit = swap::tests::submission(1, &[(0, 4, 2, surface)]);
        call(&mut endpoint, &mut ram, 0, b"A407", &submit, 0xc, true);
        dma(&mut coprocessor, &mut ram).unwrap();
        assert!(coprocessor.frame_pending() && !coprocessor.dma_pending());
        controller_call(&mut coprocessor, &mut ram, 6, Some(0));
        with_port(&mut ram, |port| coprocessor.present(port)).unwrap();
        assert_eq!(*presented.borrow(), 0);
        assert!(coprocessor.frame_pending() && !coprocessor.dma_pending());
        controller_call(&mut coprocessor, &mut ram, 6, Some(1));
        controller_call(&mut coprocessor, &mut ram, 9, None);
        with_port(&mut ram, |port| coprocessor.present(port)).unwrap();
        assert_eq!(*presented.borrow(), 0);
        assert!(coprocessor.frame_pending());
        controller_call(&mut coprocessor, &mut ram, 8, None);
        with_port(&mut ram, |port| coprocessor.present(port)).unwrap();
        assert_eq!(*presented.borrow(), 1);
        // The completion opens a coprocessor stream.
        assert!(coprocessor.dma_pending());
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        let callback = match link::Word::decode(out[0].payload).unwrap() {
            link::Word::Rpc(rpc) => rpc,
            other => panic!("expected D594, got {other:?}"),
        };
        assert!(callback.opens && callback.stream.owner == link::Owner::Dcp);
        let header_at = 0x4000 + callback.stream.calls() as usize;
        let header = link::Header::parse(ram.bytes[header_at..header_at + 12].try_into().unwrap());
        assert_eq!((&header.tag, header.input), (b"D594", 0x730));
        let complete = &ram.bytes[header_at + 12..header_at + 12 + 0x730];
        assert_eq!(&complete[..4], &1u32.to_le_bytes());
        // Decode the actual AP callback fields: zero blobs and absent
        // SwapCompleteData, so no fabricated timestamp reaches the AP.
        assert_eq!(&complete[0x727..0x72b], &[0; 4]);
        assert_eq!(complete[0x72c] & 1, 1);
        // Waiting for the AP is not runnable DMA, but still owns the stream
        // and its one-shot completion. Power/reset must not abandon it.
        assert!(!coprocessor.dma_pending() && !coprocessor.retained_idle());
        let heap = coprocessor.link.borrow().heap();
        let mut no_ack = Vec::new();
        assert_eq!(
            coprocessor.receive(
                Message {
                    endpoint: 0,
                    payload: 6 << 52 | 0x201
                },
                &mut no_ack
            ),
            Err("DCP IOP sleep with unfinished RPC, scanout or AFK work")
        );
        assert!(no_ack.is_empty());
        assert_eq!(coprocessor.rtkit.iop_power(), 0x20);
        assert!(coprocessor.stop().is_err());
        let mut no_endpoint_ack = Vec::new();
        assert!(endpoint.start(&mut no_endpoint_ack).is_err());
        assert!(no_endpoint_ack.is_empty());
        assert_eq!(coprocessor.link.borrow().heap(), heap);
        endpoint
            .receive(link::Word::Rpc(callback.answer()).encode(), &mut Vec::new())
            .unwrap();
        assert!(dma(&mut coprocessor, &mut ram).unwrap().is_empty());
        assert!(coprocessor.retained_idle());
        assert_eq!(
            coprocessor.receive(
                Message {
                    endpoint: 0,
                    payload: 6 << 52
                },
                &mut no_ack
            ),
            Err("DCP IOP memory-loss power transition is not modeled")
        );
        assert!(no_ack.is_empty());
        assert_eq!(coprocessor.rtkit.iop_power(), 0x20);
    }

    #[test]
    fn log_lines_name_the_tag_and_keep_nonzero_payload_rows() {
        let call = Log::Call {
            tag: *b"A401",
            input: Vec::new(),
            output: 4,
        };
        assert_eq!(
            alloc::format!("{call}"),
            "DCP call A401 start_signal out=0x4 in=[]"
        );
        let mut bytes = alloc::vec![0u8; 0x60];
        bytes[0x41] = 7;
        let payload = alloc::format!(
            "{}",
            Log::Payload {
                tag: *b"A407",
                bytes,
            }
        );
        let lines: Vec<&str> = payload.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("swap_submit_dcp bytes=0x60"));
        assert!(lines[1].starts_with("DCP payload A407 +0x0040 [00, 07,"));
        let lifecycle = alloc::format!(
            "{}",
            Log::Afk {
                endpoint: 0x2a,
                name: "DPTX port",
                event: afk::Event::Lifecycle([0x79, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0]),
            }
        );
        assert!(
            lifecycle
                .ends_with("lifecycle packet=[79, 00, 00, 00, 04, 00, 00, 00, 02, 00, 00, 00]")
        );
    }

    #[test]
    fn the_afk_endpoints_come_up_through_the_coprocessors_dart() {
        let (scanout, _) = screen(4, 2);
        let mut coprocessor = Coprocessor::new(scanout, Some(RAM)).unwrap();
        let mut ram = Ram::new(RAM, 0x8000);
        let shared = coprocessor.afk[0].clone();
        let mut endpoint = AfkEndpoint(shared);
        let mut sent = Vec::new();
        endpoint
            .receive(afk::INIT << 48 | 0x100, &mut sent)
            .unwrap();
        assert_eq!(afk::kind(sent[1]), afk::GETBUF);
        endpoint
            .receive(afk::GETBUF_ACK << 48 | 0x4000, &mut sent)
            .unwrap();
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        assert!(
            out.iter()
                .all(|message| message.endpoint == SYSTEM_ENDPOINT)
        );
        assert_eq!(
            out.iter().map(|m| afk::kind(m.payload)).collect::<Vec<_>>(),
            [afk::INIT_TX, afk::INIT_RX]
        );
        assert!(matches!(
            coprocessor.take_log(),
            Some(Log::Afk {
                endpoint: SYSTEM_ENDPOINT,
                event: afk::Event::Received(_),
                ..
            })
        ));
    }
}
