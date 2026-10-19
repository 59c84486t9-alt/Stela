//! The GFX coprocessor's AP-facing firmware protocol, modeled natively on two
//! RTKit application endpoints behind the generic ASC mailbox and RTKit
//! management ([`super::super::rtkit`]). Apple's `armfw_g14g` is not executed.
//!
//! Known (26A434 `AGXG14G`/`AGXFirmwareKextG14GRTBuddy`, unslid VAs; see
//! docs/research/agx.md §1):
//! - The kext matches two services named `GFXEndpoint1` and `GFXEndpoint2`
//!   (`AGXFirmwareKextRTBuddy::bootFirmware` 0x1ae9c88) and keeps endpoint
//!   **0x20** as the message endpoint and **0x21** as the doorbell
//!   (`matchedGFXEndpointGated` 0x1aea368). RTBuddy numbers application
//!   endpoint `n` as `Endpoint(n - 0x1f)`, so 0x20 is Endpoint1.
//! - After both endpoints start, the kext sends the initdata pointer on 0x20
//!   as `0x81 << 48 | (initdata_fw_va & ((1 << 44) - 1))`
//!   (`AGXArmFirmware::notifyFirmwareStarted` 0x1b44234).
//! - Work and control are asynchronous notes on 0x21:
//!   `(0x80 | type & 0x3f) << 48 | (index & 7) << 2`
//!   (`AGXArmFirmware::kickFirmware` 0x1b56c18). Public Asahi (pinned
//!   `94fb2334…`) uses type 3 (work-queue doorbell, `index` the pipe) and
//!   type 4 (firmware control).
//! - Firmware-to-AP events arrive on 0x20 and the kext accepts only
//!   `(msg >> 48) & 0x3f == 2`, the 0x42 event doorbell
//!   (`AGXArmFirmware::receivedMessageFromAKF` 0x1b44480).
//!
//! The model records the initdata pointer and each doorbell, and refuses every
//! message type it does not model rather than acknowledging it silently. It
//! never fabricates a completion: an event on 0x20 is sent only when a work
//! item has actually been executed, which this layer does not yet do, so no
//! event is produced here. The pipe of a work doorbell:

use super::super::rtkit::Endpoint;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

/// An RTKit application endpoint with its number, as [`RtKit::new`] takes them.
///
/// [`RtKit::new`]: super::super::rtkit::RtKit::new
pub type NumberedEndpoint = (u8, Box<dyn Endpoint>);

/// The message endpoint (`GFXEndpoint1`).
pub const MESSAGE_ENDPOINT: u8 = 0x20;
/// The doorbell endpoint (`GFXEndpoint2`).
pub const DOORBELL_ENDPOINT: u8 = 0x21;

const TYPE_SHIFT: u32 = 48;
/// The initdata message type on 0x20.
const MSG_INIT: u64 = 0x81;
/// Low 44 bits of the initdata message carry the firmware VA.
const INIT_VA_BITS: u64 = (1 << 44) - 1;
/// A doorbell's high bit (set in `0x80 | type`).
const DOORBELL_FLAG: u64 = 0x80;
const TYPE_MASK: u64 = 0x3f;
/// Work-queue doorbell (ring a pipe's work).
const DOORBELL_WORK: u64 = 3;
/// Firmware-control doorbell.
const DOORBELL_FWCTL: u64 = 4;
/// The event type the firmware would send on 0x20 (`0x42`).
pub const EVENT_TYPE: u64 = 0x42;

/// The work pipe a doorbell names (`index & 7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pipe {
    Vertex = 0,
    Fragment = 1,
    Compute = 2,
}

impl Pipe {
    fn from_index(index: u64) -> Option<Pipe> {
        match index {
            0 => Some(Pipe::Vertex),
            1 => Some(Pipe::Fragment),
            2 => Some(Pipe::Compute),
            _ => None,
        }
    }
}

/// The GFX firmware protocol state shared by its two endpoints.
#[derive(Debug, Default)]
pub struct State {
    /// The firmware VA of the initdata root, once the kext sends it.
    pub initdata_va: Option<u64>,
    /// Work doorbells received, in order, as (pipe, write-pointer index).
    pub work: Vec<(Pipe, u64)>,
    /// Count of firmware-control doorbells received.
    pub fwctl: u64,
}

impl State {
    fn init(&mut self, payload: u64) -> Result<(), &'static str> {
        if payload >> TYPE_SHIFT != MSG_INIT {
            return Err("AGX message endpoint models only the 0x81 initdata message");
        }
        if self.initdata_va.is_some() {
            return Err("AGX initdata sent twice");
        }
        self.initdata_va = Some(payload & INIT_VA_BITS);
        Ok(())
    }

    fn doorbell(&mut self, payload: u64) -> Result<(), &'static str> {
        let hi = payload >> TYPE_SHIFT;
        if hi & DOORBELL_FLAG == 0 {
            return Err("AGX doorbell without its 0x80 type flag");
        }
        // The kext forms (0x80 | type) << 48 | (index & 7) << 2; nothing else
        // is set.
        if payload & !(0xff << TYPE_SHIFT) & !0b11100 != 0 {
            return Err("AGX doorbell has bits outside the type and pipe index");
        }
        let index = (payload >> 2) & 7;
        match hi & TYPE_MASK {
            DOORBELL_WORK => {
                let pipe = Pipe::from_index(index).ok_or("AGX work doorbell names no pipe")?;
                // Honest: the work executor is a later layer. The doorbell is
                // recorded; no completion event is fabricated.
                self.work.push((pipe, index));
                Ok(())
            }
            DOORBELL_FWCTL => {
                self.fwctl += 1;
                Ok(())
            }
            _ => Err("AGX doorbell type is not modeled"),
        }
    }
}

/// A handle to the shared protocol state, for the DMA boundary and tests.
#[derive(Clone)]
pub struct Protocol(Rc<RefCell<State>>);

impl Protocol {
    pub fn new() -> Self {
        Protocol(Rc::new(RefCell::new(State::default())))
    }

    pub fn with<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.0.borrow())
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::new()
    }
}

/// The 0x20 message endpoint.
struct Message(Protocol);
/// The 0x21 doorbell endpoint.
struct Doorbell(Protocol);

impl Endpoint for Message {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.0.borrow_mut().init(payload)
    }
}

impl Endpoint for Doorbell {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.0.borrow_mut().doorbell(payload)
    }
}

/// The GFX coprocessor's application endpoints and a handle to their shared
/// state. Pass the endpoints to [`super::super::rtkit::RtKit::new`].
pub fn endpoints() -> (Vec<NumberedEndpoint>, Protocol) {
    let protocol = Protocol::new();
    let endpoints: Vec<NumberedEndpoint> = alloc::vec![
        (
            MESSAGE_ENDPOINT,
            Box::new(Message(protocol.clone())) as Box<dyn Endpoint>,
        ),
        (DOORBELL_ENDPOINT, Box::new(Doorbell(protocol.clone()))),
    ];
    (endpoints, protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doorbell_payload(kind: u64, index: u64) -> u64 {
        ((DOORBELL_FLAG | kind) << TYPE_SHIFT) | (index & 7) << 2
    }

    #[test]
    fn the_message_endpoint_captures_the_initdata_pointer_once() {
        let mut state = State::default();
        let va = 0x4_1234_5000;
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_ok());
        assert_eq!(state.initdata_va, Some(va));
        // A second initdata, or any other message type, is refused.
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_err());
        let mut fresh = State::default();
        assert!(fresh.init(0x42 << TYPE_SHIFT).is_err());
        // A VA above 44 bits is truncated to the field the kext sends.
        let mut wide = State::default();
        wide.init((MSG_INIT << TYPE_SHIFT) | INIT_VA_BITS | (1 << 44))
            .unwrap();
        assert_eq!(wide.initdata_va, Some(INIT_VA_BITS));
    }

    #[test]
    fn work_and_fwctl_doorbells_are_recorded_without_fabricated_events() {
        let (endpoints, protocol) = endpoints();
        let mut by_number = endpoints
            .into_iter()
            .collect::<alloc::collections::BTreeMap<_, _>>();
        let door = by_number.get_mut(&DOORBELL_ENDPOINT).unwrap();
        let mut outbox = Vec::new();
        door.receive(doorbell_payload(DOORBELL_WORK, 1), &mut outbox)
            .unwrap();
        door.receive(doorbell_payload(DOORBELL_FWCTL, 0), &mut outbox)
            .unwrap();
        // The model never answers a doorbell with a message of its own.
        assert!(outbox.is_empty());
        protocol.with(|state| {
            assert_eq!(state.work, [(Pipe::Fragment, 1)]);
            assert_eq!(state.fwctl, 1);
        });
    }

    #[test]
    fn malformed_doorbells_refuse_explicitly() {
        let mut state = State::default();
        // Missing the 0x80 flag.
        assert!(state.doorbell(DOORBELL_WORK << TYPE_SHIFT).is_err());
        // An unmodeled type.
        assert!(state.doorbell(doorbell_payload(5, 0)).is_err());
        // A pipe index of 7 names no pipe.
        assert!(state.doorbell(doorbell_payload(DOORBELL_WORK, 7)).is_err());
        // Bits outside the type and pipe fields.
        assert!(
            state
                .doorbell(doorbell_payload(DOORBELL_WORK, 0) | 0x2)
                .is_err()
        );
    }
}
