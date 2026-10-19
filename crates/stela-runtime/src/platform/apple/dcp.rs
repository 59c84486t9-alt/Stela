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
//! completes start-up at RTKit enumeration behind the boot-chain handoff.
//!
//! What is modeled and tested here: the RTKit endpoint set, the IOMFB link
//! message framing ([`link`]), the fixed-mode method/EDID answers ([`iomfb`])
//! and the swap-to-scanout presentation ([`scanout`]). The shared-region ring
//! exchange that carries the host-call payloads (an RTBuddy endpoint shared
//! buffer whose DVA the AP establishes during endpoint bring-up) is the
//! recovered-but-unvalidated boundary: until it is confirmed against a boot,
//! a type-2 RPC message refuses explicitly and names itself, rather than
//! fabricating a reply. This is a recorded gap, not a silent placeholder.
pub mod iomfb;
pub mod link;

use super::rtkit::Endpoint;
use super::scanout::{Mode, Scanout};
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The RTKit endpoint numbers the J473AP DCPEXT advertises to the AP. 0x37 is
/// the IOMFB link service (DCPEXTEndpoint24); the AFK/EPIC services are the
/// system, DPAV and DPTX-port endpoints.
pub const SYSTEM_ENDPOINT: u8 = 0x20;
pub const DPAV_ENDPOINT: u8 = 0x24;
pub const DPTX_ENDPOINT: u8 = 0x2a;
pub use link::IOMFB_ENDPOINT;

/// The IOMFB link-service endpoint: it drives one fixed connected monitor and
/// presents completed swaps to a host scanout.
pub struct Iomfb {
    scanout: Box<dyn Scanout>,
    /// Whether the AP has announced its shared heap (`link_state_init`).
    heap: Option<u64>,
}

impl Iomfb {
    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        Self {
            scanout,
            heap: None,
        }
    }

    /// The fixed mode the one connected display runs.
    pub fn mode(&self) -> Mode {
        self.scanout.mode()
    }
}

impl Endpoint for Iomfb {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        // The AP drives link bring-up (DCPLink::start → bring_up_link_service
        // → link_state_init); the coprocessor waits for its first message.
        Ok(())
    }

    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        let word = link::Word::decode(payload).ok_or("DCP link message type is not modeled")?;
        match word.kind {
            // The AP announces its shared heap increment; recorded.
            link::Kind::Heap => {
                self.heap = Some(word.length);
                Ok(())
            }
            // A state transition (ready) before any RPC; recorded.
            link::Kind::State => Ok(()),
            // An RPC message addresses the shared-region ring. The ring's DVA
            // is established by the RTBuddy endpoint shared-buffer exchange,
            // which is not yet modeled; refuse explicitly rather than fake a
            // reply. iomfb::answer / iomfb::edid / the scanout present path
            // are the recovered semantics waiting on that exchange.
            link::Kind::Message => {
                Err("DCP IOMFB RPC needs the RTBuddy shared-region exchange, not yet modeled")
            }
        }
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

/// The DCP's application endpoints, in RTKit endpoint order, for a coprocessor
/// presenting to `scanout`.
pub fn endpoints(scanout: Box<dyn Scanout>) -> Vec<(u8, Box<dyn Endpoint>)> {
    alloc::vec![
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
        (IOMFB_ENDPOINT, Box::new(Iomfb::new(scanout))),
    ]
}

#[cfg(test)]
mod tests {
    use super::super::scanout::PixelFormat;
    use super::*;

    struct TestScreen(Mode);
    impl Scanout for TestScreen {
        fn mode(&self) -> Mode {
            self.0
        }
        fn present(&mut self, _rows: &[u8]) -> Result<(), &'static str> {
            Ok(())
        }
    }

    fn iomfb() -> Iomfb {
        Iomfb::new(Box::new(TestScreen(Mode {
            width: 1920,
            height: 1080,
            format: PixelFormat::Bgra8888,
        })))
    }

    #[test]
    fn the_endpoint_records_the_heap_handshake_and_refuses_rpc_until_modeled() {
        let mut endpoint = iomfb();
        let mut outbox = Vec::new();
        // link_state_init heap announcement: (heap << 16) | 0x40.
        endpoint
            .receive(0x40 | (0x8000 << 16), &mut outbox)
            .unwrap();
        assert_eq!(endpoint.heap, Some(0x8000));
        // A type-2 RPC message refuses explicitly, not silently.
        let message = link::Word {
            kind: link::Kind::Message,
            ack: false,
            stream: Some(2),
            length: 0x40,
        };
        assert!(endpoint.receive(message.encode(), &mut outbox).is_err());
        assert!(outbox.is_empty());
    }

    #[test]
    fn the_endpoint_set_is_the_four_dcp_services() {
        let mode = Mode {
            width: 800,
            height: 600,
            format: PixelFormat::Rgba8888,
        };
        let numbers: Vec<u8> = endpoints(Box::new(TestScreen(mode)))
            .iter()
            .map(|(number, _)| *number)
            .collect();
        assert_eq!(
            numbers,
            [
                SYSTEM_ENDPOINT,
                DPAV_ENDPOINT,
                DPTX_ENDPOINT,
                IOMFB_ENDPOINT
            ]
        );
    }

    #[test]
    fn an_afk_endpoint_refuses_every_message() {
        let mut afk = Afk::new("test");
        let mut outbox = Vec::new();
        assert!(afk.receive(0, &mut outbox).is_err());
    }
}
