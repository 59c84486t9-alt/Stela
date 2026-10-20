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
//!   `(0x80 | type & 0x3f) << 48 | (index & 7) << 2 | kind`. A work doorbell
//!   (type 3) names the pipe in `kind` (TA 0, 3D 1, CL 2) and the submission
//!   index 0..4 in `index` (`AGXArmFirmware::submitTA/3D/CLChannel`
//!   0x1b56fb4/0x1b56e74/0x1b56d40); the device-control doorbell is the
//!   firmware-control type 4 with the low byte 0x11
//!   (`AGXArmFirmware::submitDeviceControl` 0x1b56bc0). The generic
//!   `kickFirmware` (0x1b56c18) forms the same layout with `kind` 0.
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
//! these endpoints, plus the firmware's bus-master accesses through the UAT in
//! the firmware context. On the initdata message it reads the root
//! ([`super::initdata::Root`]) and refuses one that is not the kext's. On the
//! device-control doorbell it consumes the device-control ring: the
//! power-transition notice (type 0x28) is recorded and the device-state query
//! (type 7) answered, each retired; every other type refuses by name and stays
//! unconsumed. On a work doorbell it runs the named data-master ring: each
//! entry's channel runs its pending commands in order. The signal commands
//! complete ([`super::signal`]), with their events posted on the firmware
//! event ring ([`super::event`]) and each announced by the 0x42 message on
//! 0x20; every command that needs the GPU refuses by its type and stays
//! pending, so no GPU work is retired and no completion is fabricated.

use super::super::asc::{Firmware, Message as Mail};
use super::super::rtkit::{Endpoint, RtKit};
use super::channel;
use super::event;
use super::initdata::{self, Root};
use super::observe::{self, Journal};
use super::ring::{self, Kind, Shared};
use super::signal;
use super::uat;
use crate::platform::dma::Port;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
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
/// The firmware-control doorbell's low byte that names the device-control
/// ring (index 4, kind 1).
const FWCTL_DEVICE_CONTROL: u64 = 0x11;
/// The initdata root's first word.
pub const INITDATA_MAGIC: u64 = initdata::MAGIC;
/// The device-control power-transition notice (`AGXAccelerator::
/// powerStateDidChangeTo`/`WillChangeTo` 0x1af8508/0x1af861c).
const DEVICE_CONTROL_POWER: u32 = 0x28;
/// The device-state query (`AGXAccelerator::getPropertyCoreConfigImpl`
/// 0x1b07768, reporting `device_state`).
const DEVICE_CONTROL_DEVICE_STATE: u32 = 0x7;
/// The device-state report's offset in the root's +0xb0 object
/// (`AGXFirmware+0x918` + 0xe000, register x27 of the query).
const DEVICE_STATE: u64 = 0xe000;
/// The report's section mask, a byte: bit 0 the PI controller and OMU metric
/// configuration at +0x31c, the others the counter list and RIF shadow at
/// +0x824. The kext reads only the sections whose bit is set and clears the
/// byte afterwards.
const DEVICE_STATE_SECTIONS: u64 = 0x82c;
/// The event type the firmware would send on 0x20 (`0x42`).
pub const EVENT_TYPE: u64 = 0x42;

/// The work pipe a doorbell names (its low two bits): the TA (vertex), 3D
/// (fragment) and CL (compute) data masters. The value is also the
/// data-master entry's command type (`encodeAcceleratorRingCommand`
/// 0x1b56be8, called with 0, 1 and 2 by `AGXFirmware::submitTA/3D/CLChannel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pipe {
    Vertex = 0,
    Fragment = 1,
    Compute = 2,
}

impl Pipe {
    fn from_kind(kind: u64) -> Option<Pipe> {
        match kind {
            0 => Some(Pipe::Vertex),
            1 => Some(Pipe::Fragment),
            2 => Some(Pipe::Compute),
            _ => None,
        }
    }
}

/// A device-control command the model carries out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Power(PowerNotice),
    DeviceState,
}

/// A power-transition notice the AP sent on the device-control ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerNotice {
    /// Word 1 is 0: the GPU's power state changed to a powered one.
    PoweredOn,
    /// Word 1 is 1: the GPU is about to change to power state 0.
    PoweringOff,
}

/// Firmware work a doorbell queued, run at the next DMA step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Job {
    DeviceControl,
    Work(Pipe, u8),
}

/// The GFX firmware protocol state shared by its two endpoints.
#[derive(Debug, Default)]
pub struct State {
    /// The firmware VA of the initdata root, once the kext sends it, as the
    /// 44-bit field of the message.
    pub initdata_va: Option<u64>,
    /// The root was read through the UAT and is the kext's.
    pub initdata_checked: bool,
    /// The root, once checked.
    pub root: Option<Root>,
    /// Work doorbells received, in order, as (pipe, submission index).
    pub work: Vec<(Pipe, u8)>,
    /// Count of device-control doorbells received.
    pub fwctl: u64,
    /// Power-transition notices consumed, in order.
    pub power: Vec<PowerNotice>,
    /// Device-state queries answered.
    pub device_state_queries: u64,
    /// Channel commands completed.
    pub commands: u64,
    /// Firmware events posted.
    pub events: u64,
    jobs: VecDeque<Job>,
    /// When observing (`--agx-observe`), the record of each work command a
    /// doorbell ran. Each is still refused by name.
    observe: Option<Journal>,
}

impl State {
    /// A fresh protocol state, observing work commands when `observe`.
    fn new(observe: bool) -> Self {
        State {
            observe: observe.then(Journal::default),
            ..Self::default()
        }
    }

    /// The observed work commands recorded this run, as log lines; empty
    /// unless `--agx-observe` and a work doorbell ran.
    pub fn observations(&mut self) -> Vec<String> {
        self.observe
            .as_mut()
            .map(Journal::drain)
            .unwrap_or_default()
    }

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
        // The kext forms (0x80 | type) << 48 | (index & 7) << 2 | kind;
        // nothing else is set.
        if payload & !(0xff << TYPE_SHIFT) & !0x1f != 0 {
            return Err("AGX doorbell has bits outside the type, index and kind");
        }
        let low = payload & 0x1f;
        let (index, kind) = ((low >> 2) as u8, low & 3);
        match hi & TYPE_MASK {
            DOORBELL_WORK => {
                let pipe = Pipe::from_kind(kind).ok_or("AGX work doorbell names no pipe")?;
                if index >= initdata::WORK_INDICES {
                    return Err("AGX work doorbell names no submission index");
                }
                self.work.push((pipe, index));
                self.jobs.push_back(Job::Work(pipe, index));
                Ok(())
            }
            DOORBELL_FWCTL if low == FWCTL_DEVICE_CONTROL => {
                self.fwctl += 1;
                self.jobs.push_back(Job::DeviceControl);
                Ok(())
            }
            DOORBELL_FWCTL => {
                Err("AGX firmware-control doorbell other than device control (0x11) is not modeled")
            }
            _ => Err("AGX doorbell type is not modeled"),
        }
    }

    /// The firmware has a bus-master access to make.
    fn dma_pending(&self) -> bool {
        (self.initdata_va.is_some() && !self.initdata_checked) || !self.jobs.is_empty()
    }

    /// Read the root, then run the queued doorbells in order.
    fn dma(&mut self, memory: &mut dyn Shared, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        if let Some(va) = self.initdata_va.filter(|_| !self.initdata_checked) {
            let root = Root::read(memory, uat::canonical_firmware_va(va))?;
            self.root = Some(root);
            self.initdata_checked = true;
        }
        while let Some(&job) = self.jobs.front() {
            let root = self
                .root
                .clone()
                .ok_or("GFX doorbell before the initdata root")?;
            match job {
                Job::DeviceControl => self.device_control(memory, &root)?,
                Job::Work(pipe, index) => self.work_ring(memory, &root, pipe, index, outbox)?,
            }
            self.jobs.pop_front();
        }
        Ok(())
    }

    /// Consume the device-control ring up to its write index.
    fn device_control(&mut self, memory: &mut dyn Shared, root: &Root) -> Result<(), &'static str> {
        let control = root.device_control(memory)?;
        let (mut read, write) = control.indices(memory)?;
        while read != write {
            let entry = control.entry(memory, Kind::DeviceControl, read)?;
            match device_control_entry(&entry)? {
                Command::Power(notice) => self.power.push(notice),
                Command::DeviceState => {
                    // The model runs no PI controller, OMU metrics, counter
                    // list or RIF shadow, so the report states no section.
                    memory.write(root.object_928 + DEVICE_STATE + DEVICE_STATE_SECTIONS, &[0])?;
                    self.device_state_queries += 1;
                }
            }
            read = ring::next(read);
            control.retire(memory, read)?;
        }
        Ok(())
    }

    /// Run a data-master ring's pending entries. Each names a channel; the
    /// channel's pending commands run in order, each retired from the
    /// channel's command ring once complete, and the entry is retired once
    /// its channel has nothing pending. A command the model does not execute
    /// refuses by name and stays pending, as does its entry.
    fn work_ring(
        &mut self,
        memory: &mut dyn Shared,
        root: &Root,
        pipe: Pipe,
        index: u8,
        outbox: &mut Vec<Mail>,
    ) -> Result<(), &'static str> {
        let work = root.work(memory, pipe, index)?;
        let (mut read, write) = work.indices(memory)?;
        while read != write {
            let entry = work.entry(memory, Kind::DataMaster, read)?;
            let command = u32::from_le_bytes(entry[0x10..0x14].try_into().unwrap());
            if command != pipe as u32 {
                return Err("GFX data-master entry's command type is not its ring's pipe");
            }
            let state = u64::from_le_bytes(entry[0x08..0x10].try_into().unwrap());
            let queue = channel::Queue::read(memory, state)?;
            while let Some(va) = queue.next(memory)? {
                let command = channel::Command::read(memory, va)?;
                // Observe (`--agx-observe`): record the command and the
                // fields observation confirms, then run it as usual — a work
                // command still refuses by name below, with its record logged.
                if let Some(journal) = self.observe.as_mut() {
                    let observation =
                        observe::Observation::record(memory, pipe as u8, index, state, va)?;
                    journal.record(&observation);
                }
                for event in signal::execute(memory, &command)? {
                    event::post(memory, root, event)?;
                    outbox.push(Mail {
                        endpoint: MESSAGE_ENDPOINT,
                        payload: EVENT_TYPE << TYPE_SHIFT,
                    });
                    self.events += 1;
                }
                queue.retire(memory)?;
                self.commands += 1;
            }
            read = ring::next(read);
            work.retire(memory, read)?;
        }
        Ok(())
    }
}

/// Decode one device-control entry (`AGFIAcceleratorDeviceControlEntry`,
/// 0x40 bytes, the type at +0). The power notice is the type and one word,
/// the device-state query the type alone; the rest is zero, as the kext builds
/// them.
fn device_control_entry(entry: &[u8]) -> Result<Command, &'static str> {
    let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
    match word(0) {
        DEVICE_CONTROL_POWER => {
            if entry[8..].iter().any(|&b| b != 0) {
                return Err("GFX device-control power notice has fields beyond its word");
            }
            match word(4) {
                0 => Ok(Command::Power(PowerNotice::PoweredOn)),
                1 => Ok(Command::Power(PowerNotice::PoweringOff)),
                _ => Err("GFX device-control power notice names no transition"),
            }
        }
        DEVICE_CONTROL_DEVICE_STATE => {
            if entry[4..].iter().any(|&b| b != 0) {
                return Err("GFX device-state query has fields beyond its type");
            }
            Ok(Command::DeviceState)
        }
        // AGXAccelerator::allocateMemoryEvent answers a host-allocation
        // request the firmware raised; the model raises none.
        0x8 | 0x26 => Err(
            "GFX device control 0x8/0x26 answers a firmware host-allocation request the model never makes",
        ),
        _ => Err("GFX device-control type is not one the 26A434 kext sends"),
    }
}

/// A handle to the shared protocol state, for the DMA boundary and tests.
#[derive(Clone)]
pub struct Protocol(Rc<RefCell<State>>);

impl Protocol {
    pub fn new() -> Self {
        Protocol::with_observe(false)
    }

    /// A protocol whose firmware records work commands (`--agx-observe`).
    pub fn with_observe(observe: bool) -> Self {
        Protocol(Rc::new(RefCell::new(State::new(observe))))
    }

    pub fn with<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.0.borrow())
    }

    /// Drain the observed work commands recorded this run, as log lines.
    pub fn observations(&self) -> Vec<String> {
        self.0.borrow_mut().observations()
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
        Self::with_observe(false)
    }

    /// A GFX coprocessor that records each work command (`--agx-observe`)
    /// when `observe`, still refusing it by name.
    pub fn with_observe(observe: bool) -> Result<Self, &'static str> {
        let (endpoints, protocol) = endpoints(observe);
        let rtkit = RtKit::new(endpoints, super::super::rtkit::Management::Ordinary)?;
        Ok(Self { rtkit, protocol })
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Drain the observed work commands recorded this run, as log lines.
    pub fn observations(&mut self) -> Vec<String> {
        self.protocol.observations()
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
    fn dma(&mut self, port: &mut Port<'_, '_>, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        self.protocol.0.borrow_mut().dma(port, outbox)
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
pub fn endpoints(observe: bool) -> (Vec<NumberedEndpoint>, Protocol) {
    let protocol = Protocol::with_observe(observe);
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
    use crate::platform::apple::agx::initdata::tests::{BASE, RINGS, ROOT, kext_root};
    use crate::platform::apple::agx::ring::tests::Flat;
    use crate::platform::apple::agx::ring::{READ, WRITE};

    fn doorbell_payload(kind: u64, low: u64) -> u64 {
        ((DOORBELL_FLAG | kind) << TYPE_SHIFT) | low
    }

    fn work(pipe: u64, index: u64) -> u64 {
        doorbell_payload(DOORBELL_WORK, (index & 7) << 2 | pipe)
    }

    const CONTROL_STATE: u64 = BASE + 0x8000;
    const CONTROL_ENTRIES: u64 = BASE + 0xa000;

    /// A checked root whose device-control ring holds `entries`.
    fn with_device_control(entries: &[[u8; 0x40]]) -> (State, Flat) {
        let mut memory = Flat::new(BASE, 0x20000);
        kext_root(&mut memory);
        memory.put_descriptor(RINGS + 0x1a0, CONTROL_STATE, CONTROL_ENTRIES);
        for (n, entry) in entries.iter().enumerate() {
            memory.put(CONTROL_ENTRIES + n as u64 * 0x40, entry);
        }
        memory.put_u32(CONTROL_STATE + WRITE, entries.len() as u32);
        let mut state = State::default();
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        (state, memory)
    }

    fn power(word: u32) -> [u8; 0x40] {
        let mut entry = [0; 0x40];
        entry[..4].copy_from_slice(&DEVICE_CONTROL_POWER.to_le_bytes());
        entry[4..8].copy_from_slice(&word.to_le_bytes());
        entry
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
    fn doorbells_take_the_kexts_forms_and_queue_firmware_work() {
        let (endpoints, protocol) = endpoints(false);
        let mut by_number = endpoints
            .into_iter()
            .collect::<alloc::collections::BTreeMap<_, _>>();
        let door = by_number.get_mut(&DOORBELL_ENDPOINT).unwrap();
        let mut outbox = Vec::new();
        // submit3DChannel at index 2, then submitDeviceControl's 0x84 << 48 | 0x11.
        door.receive(work(1, 2), &mut outbox).unwrap();
        door.receive(doorbell_payload(DOORBELL_FWCTL, 0x11), &mut outbox)
            .unwrap();
        // The model never answers a doorbell with a message of its own.
        assert!(outbox.is_empty());
        protocol.with(|state| {
            assert_eq!(state.work, [(Pipe::Fragment, 2)]);
            assert_eq!(state.fwctl, 1);
            assert!(state.dma_pending());
        });
    }

    #[test]
    fn malformed_or_unmodeled_doorbells_refuse_explicitly() {
        let mut state = State::default();
        // Missing the 0x80 flag.
        assert!(state.doorbell(DOORBELL_WORK << TYPE_SHIFT).is_err());
        // An unmodeled type.
        assert!(state.doorbell(doorbell_payload(5, 0)).is_err());
        // Kind 3 names no pipe; index 4 no submission ring.
        assert!(state.doorbell(work(3, 0)).is_err());
        assert!(state.doorbell(work(0, 4)).is_err());
        // Bits outside the type, index and kind.
        assert!(state.doorbell(work(0, 0) | 0x20).is_err());
        // A firmware-control doorbell other than device control.
        assert!(state.doorbell(doorbell_payload(DOORBELL_FWCTL, 0)).is_err());
        assert!(state.work.is_empty() && !state.dma_pending());
    }

    #[test]
    fn power_notices_are_consumed_from_the_device_control_ring() {
        let (mut state, mut memory) = with_device_control(&[power(1), power(0)]);
        state
            .doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))
            .unwrap();
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        assert_eq!(
            state.power,
            [PowerNotice::PoweringOff, PowerNotice::PoweredOn]
        );
        // waitForDeviceControlCompletion sees the read index reach the write
        // index.
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(2));
        assert!(!state.dma_pending());
    }

    #[test]
    fn the_device_state_query_reports_no_section() {
        let mut query = [0; 0x40];
        query[0] = 7;
        let (mut state, mut memory) = with_device_control(&[query]);
        // A stale mask from an earlier report.
        let sections = BASE + 0x5000 + DEVICE_STATE + DEVICE_STATE_SECTIONS;
        memory.put(sections, &[1]);
        state
            .doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))
            .unwrap();
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        let mut mask = [0xff];
        memory.read(sections, &mut mask).unwrap();
        assert_eq!(mask, [0]);
        assert_eq!(state.device_state_queries, 1);
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(1));
        query[8] = 1;
        assert!(device_control_entry(&query).is_err());
    }

    #[test]
    fn unmodeled_device_control_stays_unconsumed_and_refuses_by_name() {
        let mut event = [0; 0x40];
        event[0] = 8;
        let (mut state, mut memory) = with_device_control(&[power(0), event]);
        state
            .doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))
            .unwrap();
        assert!(
            state
                .dma(&mut memory, &mut Vec::new())
                .unwrap_err()
                .contains("host-allocation")
        );
        // The power notice before it was retired; the memory event was not.
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(1));
        let mut extra = power(0);
        extra[0x20] = 1;
        assert!(device_control_entry(&extra).is_err());
        assert!(device_control_entry(&power(2)).is_err());
    }

    /// The 3D ring at submission index 0 with one entry naming the channel
    /// at `channel_state`, whose queue holds one command at `command`.
    fn one_3d_entry(memory: &mut Flat, channel_state: u64, command: u64) -> (u64, u64) {
        let (ring_state, entries) = (BASE + 0x9000, BASE + 0xc000);
        memory.put_descriptor(RINGS + 0x20 + 0x20, ring_state, entries);
        memory.put_u32(entries + 0x10, 1);
        memory.put_u32(ring_state + WRITE, 1);
        if channel_state != 0 {
            crate::platform::apple::agx::channel::tests::one_command(
                memory,
                channel_state,
                command,
            );
            memory.put_u64(entries + 0x08, channel_state);
        }
        (ring_state, entries)
    }

    #[test]
    fn unexecuted_work_refuses_rather_than_completing() {
        let (mut state, mut memory) = with_device_control(&[]);
        let (ring_state, _) = one_3d_entry(&mut memory, 0, 0);
        state.doorbell(work(1, 0)).unwrap();
        // The entry names no channel yet.
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX data-master entry names no channel state")
        );
        // A channel whose next command is a 3D command.
        let (channel_state, command) = (BASE + 0xd000, BASE + 0x10000);
        one_3d_entry(&mut memory, channel_state, command);
        memory.put_u32(command, 1);
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX 3D command (type 1) is not executed")
        );
        assert_eq!(memory.read_u32(ring_state + READ), Ok(0));
        assert_eq!(memory.read_u32(channel_state + 0x1000), Ok(0));
        // An empty ring has nothing to refuse.
        let mut idle = with_device_control(&[]);
        memory.put_descriptor(RINGS + 0x20, ring_state + 0x100, BASE + 0xc000);
        idle.1 = memory;
        idle.0.doorbell(work(0, 0)).unwrap();
        idle.0.dma(&mut idle.1, &mut Vec::new()).unwrap();
    }

    #[test]
    fn a_shared_event_signal_completes_and_posts_its_events() {
        use crate::platform::apple::agx::event::Event;
        use crate::platform::apple::agx::event::tests::{EVENT_STATE, entry, event_ring};
        let (mut state, mut memory) = with_device_control(&[]);
        event_ring(&mut memory);
        let (channel_state, command) = (BASE + 0xd000, BASE + 0x10000);
        let (ring_state, _) = one_3d_entry(&mut memory, channel_state, command);
        let (stream, shared) = (command + 0x400, command + 0x800);
        memory.put_u32(command, 9);
        memory.put_u64(command + 0x1c, stream);
        memory.put_u64(command + 0x30, command + 0x900);
        memory.put_u64(command + 0x38, command + 0x908);
        memory.put_u32(command + 0x40, 0x100);
        memory.put_u32(command + 0x44, 2);
        memory.put_u32(stream, 0xe);
        memory.put_u64(stream + 0x10, 0x55);
        memory.put_u64(stream + 0x18, 1);
        memory.put_u64(stream + 0x28, shared);
        memory.put_u64(stream + 0x30, command + 0x908);
        memory.put_u32(stream + 0x38, 0x100);
        memory.put_u32(stream + 0x4c, 0x4000_0002);
        state.doorbell(work(1, 0)).unwrap();
        let mut outbox = Vec::new();
        state.dma(&mut memory, &mut outbox).unwrap();
        // Two events, each announced by the 0x42 message on 0x20.
        assert_eq!(
            outbox,
            [Mail {
                endpoint: MESSAGE_ENDPOINT,
                payload: EVENT_TYPE << TYPE_SHIFT
            }; 2]
        );
        assert_eq!(memory.read_u32(EVENT_STATE + WRITE), Ok(2));
        assert_eq!(
            entry(&mut memory, 0),
            Event::SharedSignal {
                id: 0x55,
                value: 1,
                flag: 0
            }
            .encode()
        );
        assert_eq!(entry(&mut memory, 1), Event::Flag(1 << 2).encode());
        assert_eq!(memory.read_u64(shared), Ok(1));
        assert_eq!(memory.read_u32(command + 0x900), Ok(0x100));
        // The command and the data-master entry are retired.
        assert_eq!(memory.read_u32(channel_state + 0x1000), Ok(1));
        assert_eq!(memory.read_u32(ring_state + READ), Ok(1));
        assert_eq!((state.commands, state.events), (1, 2));
    }

    #[test]
    fn observe_records_the_refused_work_command_and_its_fields() {
        let mut memory = Flat::new(BASE, 0x20000);
        kext_root(&mut memory);
        memory.put_descriptor(RINGS + 0x1a0, CONTROL_STATE, CONTROL_ENTRIES);
        let mut state = State::new(true);
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        // A 3D command naming a VDM stream at +0x14 (channel.rs 3D +0x14).
        let (channel_state, command) = (BASE + 0xd000, BASE + 0x10000);
        one_3d_entry(&mut memory, channel_state, command);
        memory.put_u32(command, 1);
        let stream = command + 0x400;
        memory.put_u64(command + 0x14, stream);
        for (i, word) in [
            3u32 << 29 | 6 << 8 | 1 << 22 | 1 << 23 | 1 << 24,
            3,
            1,
            0,
            6 << 29,
        ]
        .into_iter()
        .enumerate()
        {
            memory.put_u32(stream + 4 * i as u64, word);
        }
        state.doorbell(work(1, 0)).unwrap();
        // The command still refuses by name: no fake completion.
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX 3D command (type 1) is not executed")
        );
        let lines = state.observations();
        assert!(lines[0].starts_with("AGX OBSERVE pipe=1 index=0"));
        assert!(lines.iter().any(|l| l.contains("ThreeD")));
        assert!(lines.iter().any(|l| l.contains("VDM control stream")));
        // Draining twice yields nothing the second time.
        assert!(state.observations().is_empty());
        // Off by default: no records without observe.
        let mut quiet = State::default();
        assert!(quiet.observations().is_empty());
    }

    #[test]
    fn the_root_must_be_the_kexts_before_any_doorbell_runs() {
        let mut memory = Flat::new(BASE, 0x20000);
        let mut state = State::default();
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX initdata root lacks its magic")
        );
        assert!(state.dma_pending());
        let mut early = State::default();
        early
            .doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))
            .unwrap();
        assert!(early.dma(&mut memory, &mut Vec::new()).is_err());
    }

    #[test]
    fn the_initdata_root_is_read_through_the_uat() {
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
            state.dma(&mut port, &mut Vec::new())
        };
        // A root without the magic refuses and stays pending.
        assert!(run(&mut state, &mut ram, &mut table).is_err());
        assert!(state.dma_pending());
        put_root(&mut ram, base + 0x1_0000, va);
        run(&mut state, &mut ram, &mut table).unwrap();
        assert!(state.initdata_checked && !state.dma_pending());
        assert_eq!(
            state.root.as_ref().map(|root| root.rings),
            Some(va + 0x1000)
        );
    }

    /// Write a kext-shaped root at physical `at` whose objects follow `va`.
    pub(crate) fn put_root(ram: &mut crate::platform::dma::tests::Ram, at: u64, va: u64) {
        ram.put_u64(at, INITDATA_MAGIC);
        ram.put_u64(at + 0x28, 1 << 32);
        for (n, field) in [0x08, 0x18, 0x20, 0xa8, 0xb0, 0xb8, 0xc0]
            .into_iter()
            .enumerate()
        {
            ram.put_u64(at + field, va + 0x1000 * (n as u64 + 1));
        }
        // +0x18, the ring directory, is the second object.
        ram.put_u64(at + 0x18, va + 0x1000);
    }
}
