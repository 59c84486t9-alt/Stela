//! The `dcpext` display coprocessor: the common ASC wrapper ([`super::asc`])
//! carrying an RTKit ([`super::rtkit`]) whose application endpoints are the
//! J473AP DCP's — the IOMFB link service (0x37) and the AFK/EPIC services
//! (0x20 system, 0x24 DPAV, 0x2a DPTX port). The model terminates the
//! pipeline at the AP boundary: it answers the unchanged IOMobileFramebuffer
//! stack's host calls and drives one fixed, connected SDR monitor, presenting
//! each completed swap to a host [`scanout::Scanout`]. It never runs
//! `ipad14dcp` firmware.
//!
//! docs/research/display-gpu.md owns the recovered contract. The DCPEXT nub
//! is `quiesced` and `user-power-managed`, so (like the SMC) the coprocessor
//! acknowledges the AP's wake once RTKit enumeration completes behind the
//! boot-chain handoff.
//!
//! What is modeled and tested here: the RTKit endpoint set, the IOMFB link
//! ([`link`] wire format, [`rpc`] coprocessor-side engine: hello, the
//! region announcement, ready, the AP's calls, nested callbacks and
//! answers) reaching the AP's shared region through `dart-dcpext`, the
//! fixed-mode method/EDID answers ([`iomfb`]) and the swap-to-scanout
//! presentation ([`scanout`]). The swap host calls need the
//! `dart-dispext0` surface path and refuse by name until it is modeled.
pub mod iomfb;
pub mod link;
pub mod rpc;

use super::asc::{Firmware, Message, TransitionRequest};
use super::rtkit::{Endpoint, Management, RtKit};
use super::scanout::{Mode, Scanout};
use crate::platform::dma::Port;
use alloc::boxed::Box;
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::cell::RefCell;

/// The RTKit endpoint numbers the J473AP DCPEXT advertises to the AP. 0x37 is
/// the IOMFB link service (DCPEXTEndpoint24); the AFK/EPIC services are the
/// system, DPAV and DPTX-port endpoints.
pub const SYSTEM_ENDPOINT: u8 = 0x20;
pub const DPAV_ENDPOINT: u8 = 0x24;
pub const DPTX_ENDPOINT: u8 = 0x2a;
pub use link::IOMFB_ENDPOINT;

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

/// A `dma::Port` as the link's bus.
struct PortBus<'p, 'a, 'b>(&'p mut Port<'a, 'b>);

impl rpc::Bus for PortBus<'_, '_, '_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        self.0
            .read(address, buffer)
            .map_err(|_| "DCP shared-region read faulted through dart-dcpext")
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str> {
        self.0
            .write(address, data)
            .map_err(|_| "DCP shared-region write faulted through dart-dcpext")
    }
}

/// The DCPEXT coprocessor: RTKit with the DCP endpoints, and the link's DMA
/// through `dart-dcpext`.
pub struct Coprocessor {
    rtkit: RtKit,
    link: Shared,
}

impl Coprocessor {
    /// A coprocessor presenting to `scanout`. `window` is `dart-dcpext`'s
    /// `vm-base` when the node is `truncate-dvas`: `AppleA7IOP::_restrictDVA`
    /// (kernel file 0x1bb1424) then hands the coprocessor only a DVA's low
    /// 32 bits, which lie in that window.
    pub fn new(scanout: Box<dyn Scanout>, window: Option<u64>) -> Result<Self, &'static str> {
        let link = Rc::new(RefCell::new(rpc::Link::new(
            iomfb::Methods::new(scanout),
            window,
        )));
        let endpoints = alloc::vec![
            (
                SYSTEM_ENDPOINT,
                Box::new(Afk::new("DCP system AFK endpoint is not modeled")) as Box<dyn Endpoint>,
            ),
            (
                DPAV_ENDPOINT,
                Box::new(Afk::new("DCP DPAV EPIC endpoint is not modeled")),
            ),
            (
                DPTX_ENDPOINT,
                Box::new(Afk::new("DCP DPTX-port EPIC endpoint is not modeled")),
            ),
            (IOMFB_ENDPOINT, Box::new(Iomfb(link.clone()))),
        ];
        let rtkit = RtKit::new(endpoints, Management::Ordinary)?;
        Ok(Self { rtkit, link })
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
}

impl Firmware for Coprocessor {
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.start(outbox)
    }
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.receive(message, outbox)
    }
    fn dma_pending(&self) -> bool {
        self.link.borrow().pending()
    }
    fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        let mut sent = Vec::new();
        self.link.borrow_mut().dma(&mut PortBus(port), &mut sent)?;
        outbox.extend(sent.into_iter().map(|payload| Message {
            endpoint: IOMFB_ENDPOINT,
            payload,
        }));
        Ok(())
    }
    fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rtkit.poll(outbox)
    }
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        self.rtkit.take_transition()
    }
}

/// An AFK/EPIC endpoint of the DCP the model does not yet serve (the system,
/// DPAV and DPTX-port services). It refuses every message, named, so the gap
/// is recorded rather than a protocol faked.
pub struct Afk {
    reason: &'static str,
}

impl Afk {
    pub fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Endpoint for Afk {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }

    fn receive(&mut self, _payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Err(self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::super::scanout::PixelFormat;
    use super::*;
    use crate::platform::dma::{DmaError, tests::Ram};

    const RAM: u64 = 0x8_0000_0000;

    struct TestScreen(Mode);
    impl Scanout for TestScreen {
        fn mode(&self) -> Mode {
            self.0
        }
        fn present(&mut self, _rows: &[u8]) -> Result<(), &'static str> {
            Ok(())
        }
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

    fn dma(coprocessor: &mut Coprocessor, ram: &mut Ram) -> Result<Vec<Message>, &'static str> {
        let mut latch = super::super::interrupt::InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Identity,
            stream: 5,
            memory: ram,
            access: &mut access,
        };
        let mut outbox = Vec::new();
        coprocessor.dma(&mut port, &mut outbox)?;
        Ok(outbox)
    }

    #[test]
    fn the_link_comes_up_and_answers_through_the_coprocessors_dart() {
        let screen = TestScreen(Mode {
            width: 1920,
            height: 1080,
            format: PixelFormat::Bgra8888,
        });
        let mut coprocessor = Coprocessor::new(Box::new(screen), Some(RAM)).unwrap();
        let mut endpoint = Iomfb(coprocessor.link.clone());
        let mut sent = Vec::new();
        endpoint.start(&mut sent).unwrap();
        assert_eq!(sent, [0x100 | 211 << 16]);
        // The AP's region at DVA 0x4000 (truncated), header at its start.
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        ram.bytes[0x4000 + 12] = 4;
        endpoint
            .receive(link::Word::Region { dva: 0x4000 }.encode(), &mut sent)
            .unwrap();
        assert!(coprocessor.dma_pending());
        let ready = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(ready[0].endpoint, IOMFB_ENDPOINT);
        assert_eq!(ready[0].payload & 3, 1);
        // display_width on AP stream 1.
        let header = link::Header {
            tag: *b"A451",
            input: 0,
            output: 4,
        };
        let at = 0x4000 + 0x8000;
        ram.bytes[at..at + 12].copy_from_slice(&header.bytes());
        let call = link::Rpc {
            answer: false,
            stream: link::Stream {
                owner: link::Owner::Ap,
                index: 1,
            },
            opens: true,
            offset: 0,
            length: 16,
            token: 0,
        };
        endpoint
            .receive(link::Word::Rpc(call).encode(), &mut sent)
            .unwrap();
        let answer = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(answer[0].payload, link::Word::Rpc(call.answer()).encode());
        assert_eq!(&ram.bytes[at + 12..at + 16], &1920u32.to_le_bytes());
        assert!(!coprocessor.dma_pending());
    }

    #[test]
    fn start_signal_nests_start_hardware_boot_through_the_coprocessor() {
        // The AP's real start path: hello -> region -> ready -> A401
        // start_signal (which the coprocessor answers by nesting D120
        // start_hardware_boot), inside which the AP nests A451 display_width,
        // then answers D120 so A401 returns success. Driven end to end through
        // dcp::Coprocessor and its DART, as the AP library would.
        let screen = TestScreen(Mode {
            width: 1920,
            height: 1080,
            format: PixelFormat::Bgra8888,
        });
        let mut coprocessor = Coprocessor::new(Box::new(screen), Some(RAM)).unwrap();
        let mut endpoint = Iomfb(coprocessor.link.clone());
        let mut sent = Vec::new();
        endpoint.start(&mut sent).unwrap();
        let mut ram = Ram::new(RAM, 0x4000 + link::REGION_BYTES as usize);
        ram.bytes[0x4000 + 12] = 4;
        endpoint
            .receive(link::Word::Region { dva: 0x4000 }.encode(), &mut sent)
            .unwrap();
        dma(&mut coprocessor, &mut ram).unwrap();

        let ap1 = link::Stream {
            owner: link::Owner::Ap,
            index: 1,
        };
        // A401 start_signal (in=0 out=4), opening AP stream 1 at its base.
        let a401_at = 0x4000 + ap1.calls() as usize;
        ram.bytes[a401_at..a401_at + 12].copy_from_slice(
            &link::Header {
                tag: *b"A401",
                input: 0,
                output: 4,
            }
            .bytes(),
        );
        let a401 = link::Rpc {
            answer: false,
            stream: ap1,
            opens: true,
            offset: 0,
            length: 16,
            token: 0,
        };
        endpoint
            .receive(link::Word::Rpc(a401).encode(), &mut sent)
            .unwrap();
        // The coprocessor nests D120 start_hardware_boot into the AP, written
        // into the coprocessor's buffer of AP stream 1 (0x60000 + 0x8000),
        // not opening anything.
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        let d120 = match link::Word::decode(out[0].payload).unwrap() {
            link::Word::Rpc(rpc) => rpc,
            other => panic!("expected the D120 callback, got {other:?}"),
        };
        assert!(!d120.answer && !d120.opens && d120.stream == ap1);
        let d120_at = 0x4000 + ap1.nested() as usize + d120.offset as usize;
        assert_eq!(
            &link::Header::parse(ram.bytes[d120_at..d120_at + 12].try_into().unwrap()).tag,
            b"D120"
        );

        // Serving D120, the AP nests A451 display_width above A401 in its own
        // stream-1 calls buffer; the coprocessor answers it in place.
        let a451_at = 0x4000 + ap1.calls() as usize + 0x40;
        ram.bytes[a451_at..a451_at + 12].copy_from_slice(
            &link::Header {
                tag: *b"A451",
                input: 0,
                output: 4,
            }
            .bytes(),
        );
        let a451 = link::Rpc {
            offset: 0x40,
            opens: false,
            ..a401
        };
        endpoint
            .receive(link::Word::Rpc(a451).encode(), &mut sent)
            .unwrap();
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        assert_eq!(out[0].payload, link::Word::Rpc(a451.answer()).encode());
        assert_eq!(
            &ram.bytes[a451_at + 12..a451_at + 16],
            &1920u32.to_le_bytes()
        );

        // The AP answers D120 with success; A401 then returns success.
        ram.bytes[d120_at + 12..d120_at + 16].copy_from_slice(&1u32.to_le_bytes());
        endpoint
            .receive(link::Word::Rpc(d120.answer()).encode(), &mut sent)
            .unwrap();
        let out = dma(&mut coprocessor, &mut ram).unwrap();
        let a401_answer = match link::Word::decode(out[0].payload).unwrap() {
            link::Word::Rpc(rpc) => rpc,
            other => panic!("expected the A401 answer, got {other:?}"),
        };
        assert!(a401_answer.answer && a401_answer.opens);
        assert_eq!(&ram.bytes[a401_at + 12..a401_at + 16], &1u32.to_le_bytes());
        assert!(!coprocessor.dma_pending());
    }

    #[test]
    fn an_afk_endpoint_refuses_every_message() {
        let mut afk = Afk::new("test");
        let mut outbox = Vec::new();
        assert!(afk.receive(0, &mut outbox).is_err());
    }
}
