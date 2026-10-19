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
//! - The initdata root the pointer names is one page whose first word is the
//!   magic `0x0c8a_6342_8392_04c8` (`AGXArmFirmware::initFirmwareData`
//!   0x1b5b36c, the page at `firmware+0x1630` that `notifyFirmwareStarted`
//!   names).
//!
//! [`Coprocessor`] is the whole GFX coprocessor behind the ASC: RTKit with
//! these endpoints, plus the firmware's bus-master reads through the UAT in
//! the firmware context. On the initdata message it reads the root's magic
//! through the UAT and refuses a root that lacks it.
//!
//! The model records the initdata pointer and each doorbell, and refuses every
//! message type it does not model rather than acknowledging it silently. It
//! never fabricates a completion: an event on 0x20 is sent only when a work
//! item has actually been executed, which this layer does not yet do, so no
//! event is produced here. The pipe of a work doorbell:

use super::super::asc::{Firmware, Message as Mail};
use super::super::rtkit::{Endpoint, RtKit};
use super::uat;
use crate::platform::dma::{DmaError, Port};
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
/// The initdata root's first word.
pub const INITDATA_MAGIC: u64 = 0x0c8a_6342_8392_04c8;
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
    /// The firmware VA of the initdata root, once the kext sends it, as the
    /// 44-bit field of the message.
    pub initdata_va: Option<u64>,
    /// The root's magic was read through the UAT and matched.
    pub initdata_checked: bool,
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

impl State {
    /// The firmware has a bus-master read to make.
    fn dma_pending(&self) -> bool {
        self.initdata_va.is_some() && !self.initdata_checked
    }

    /// Read the initdata root's magic through the UAT.
    fn dma(&mut self, port: &mut Port<'_, '_>) -> Result<(), &'static str> {
        let Some(va) = self.initdata_va.filter(|_| !self.initdata_checked) else {
            return Ok(());
        };
        let mut word = [0; 8];
        port.read(uat::canonical_firmware_va(va), &mut word)
            .map_err(|error| match error {
                DmaError::Fault(_) => "GFX initdata root faults in the UAT",
                DmaError::Memory => "GFX initdata root is not RAM",
                DmaError::Unsupported(reason) => reason,
            })?;
        if u64::from_le_bytes(word) != INITDATA_MAGIC {
            return Err("GFX initdata root lacks its magic");
        }
        self.initdata_checked = true;
        Ok(())
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

/// The GFX coprocessor: RTKit with the GFX endpoints and the firmware's DMA.
pub struct Coprocessor {
    rtkit: RtKit,
    protocol: Protocol,
}

impl Coprocessor {
    /// A GFX coprocessor whose RTKit manages its power ordinarily
    /// (`power-managed`).
    pub fn new() -> Result<Self, &'static str> {
        let (endpoints, protocol) = endpoints();
        let rtkit = RtKit::new(endpoints, super::super::rtkit::Management::Ordinary)?;
        Ok(Self { rtkit, protocol })
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

impl Firmware for Coprocessor {
    fn start(&mut self, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        self.rtkit.start(outbox)
    }
    fn receive(&mut self, message: Mail, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        self.rtkit.receive(message, outbox)
    }
    fn dma_pending(&self) -> bool {
        self.protocol.with(State::dma_pending)
    }
    fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        _outbox: &mut Vec<Mail>,
    ) -> Result<(), &'static str> {
        self.protocol.0.borrow_mut().dma(port)
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

    #[test]
    fn the_initdata_root_is_checked_through_the_uat() {
        use crate::platform::apple::bus::Access;
        use crate::platform::apple::interrupt::InterruptLatch;
        use crate::platform::dma::tests::Ram;
        use uat::{Access as Ap, Agent, Flags, MemoryAttr, Uat};
        // TTBAT, PCE, PDE, PTE and the initdata page.
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 0x4000 * 5);
        let va = 0xffff_ffa0_0000_0000;
        let (_, idx) = uat::indices(va);
        let [ttbr0, ttbr1] = uat::encode_gptbat(0, 0, base + 0x4000);
        ram.put_u64(base, ttbr0);
        ram.put_u64(base + 8, ttbr1);
        ram.put_u64(
            base + 0x4000 + idx[0] as u64 * 8,
            uat::encode_table(base + 0x8000),
        );
        ram.put_u64(
            base + 0x8000 + idx[1] as u64 * 8,
            uat::encode_table(base + 0xc000),
        );
        let flags = Flags {
            access: Ap::Firmware,
            memory: MemoryAttr::Uncached,
            global: true,
            pxn: false,
            uxn: true,
            gpu_access: true,
        };
        ram.put_u64(
            base + 0xc000 + idx[2] as u64 * 8,
            uat::encode_pte(base + 0x1_0000, &flags),
        );
        let mut table = Uat::default();
        table.configure(base).unwrap();
        let mut latch = InterruptLatch::new();
        let mut state = State::default();
        state
            .init((MSG_INIT << TYPE_SHIFT) | (va & INIT_VA_BITS))
            .unwrap();
        assert!(state.dma_pending());
        let mut run = |state: &mut State, ram: &mut Ram, table: &mut Uat| {
            let mut access = Access::new(0, 0, &mut latch);
            let mut view = table.agent(Agent::Firmware);
            let mut port = Port {
                iommu: &mut view,
                stream: uat::FIRMWARE_CONTEXT,
                memory: ram,
                access: &mut access,
            };
            state.dma(&mut port)
        };
        // A root without the magic refuses and stays pending.
        assert!(run(&mut state, &mut ram, &mut table).is_err());
        assert!(state.dma_pending());
        ram.put_u64(base + 0x1_0000, INITDATA_MAGIC);
        run(&mut state, &mut ram, &mut table).unwrap();
        assert!(state.initdata_checked && !state.dma_pending());
    }
}
