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
//! - [`afk`]: the AFK ring transport of the EPIC endpoints, up with no
//!   service announced.
//!
//! Every call, callback, refusal and AFK message is recorded in a bounded
//! display [`Log`] the boot engine prints, so a boot shows what the guest
//! sent the model at the first named refusal.
pub mod abi;
pub mod afk;
pub mod iomfb;
pub mod link;
pub mod modes;
pub mod rpc;
pub mod swap;

use super::asc::{Firmware, Message, TransitionRequest};
use super::rtkit::{Endpoint, Management, RtKit};
use super::scanout::{Mode, Scanout, Surface};
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
pub use link::IOMFB_ENDPOINT;

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
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        outbox.push(self.0.borrow_mut().start());
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
    pub fn new(scanout: Box<dyn Scanout>, window: Option<u64>) -> Result<Self, &'static str> {
        Self::with_methods(iomfb::Methods::new(scanout), window)
    }

    fn with_methods(methods: iomfb::Methods, window: Option<u64>) -> Result<Self, &'static str> {
        let link = Rc::new(RefCell::new(rpc::Link::new(methods, window)));
        let afk: Vec<_> = AFK_ENDPOINTS
            .iter()
            .map(|&(endpoint, name)| Rc::new(RefCell::new(afk::Afk::new(endpoint, name, window))))
            .collect();
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
        let rtkit = RtKit::new(endpoints, Management::Ordinary)?;
        Ok(Self { rtkit, link, afk })
    }

    /// The coprocessor was used and quiesced by the boot chain.
    pub fn quiesced(mut self) -> Self {
        self.rtkit = self.rtkit.quiesced();
        self
    }

    /// The fixed mode the one connected display runs.
    pub fn mode(&self) -> Mode {
        self.link.borrow().service().mode()
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
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.start(outbox)
    }
    fn stop(&mut self) -> Result<(), &'static str> {
        if self.link.borrow().pending()
            || self.frame_pending()
            || self.afk.iter().any(|afk| !afk.borrow().retained_idle())
        {
            return Err("DCP CPU stop with unfinished RPC, scanout or AFK work");
        }
        self.rtkit.stop()
    }
    fn resume(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        // CPU RUN alone resumes execution; the later IOP wake message
        // releases the retained RPC link through receive's power edge.
        self.rtkit.resume(outbox)
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
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
            iop_power(&mut coprocessor, 0).unwrap();
            iop_power(&mut coprocessor, 0x220).unwrap();
            assert!(quiesced(&coprocessor.link));
        }
    }

    #[test]
    fn asc_cpu_halt_and_restart_preserve_the_dcp_link_until_iop_wake() {
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
        asc.write(0x8114, Width::Word, 1, &mut access).unwrap();
        assert!(asc.read(0x8830, Width::Double, &mut access).is_err());
        assert!(quiesced(&shared)); // CPU resume alone does not wake the link.
        send(&mut asc, &mut access, 0, 6 << 52 | 0x220);
        assert_eq!(take(&mut asc, &mut access), 7 << 52 | 0x220);
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

    #[test]
    fn a_presented_swap_completes_on_a_coprocessor_stream() {
        let (scanout, presented) = screen(4, 2);
        let methods = iomfb::Methods::new(scanout);
        let mut coprocessor = Coprocessor::with_methods(methods, Some(RAM)).unwrap();
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize + 0x4000);
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
