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
//! device-control doorbell it consumes the device-control ring: every type
//! the 26A434 kext sends is decoded against the firmware's dispatcher, its
//! shared effects reproduced and its entry retired and counted; the types
//! whose effects need a unit or firmware thread the model lacks refuse by
//! name and stay unconsumed. On a work doorbell it runs the named data-master ring: each
//! entry's channel runs its pending commands in order. The signal commands
//! complete ([`super::signal`]), with their events posted on the firmware
//! event ring ([`super::event`]) and each announced by the 0x42 message on
//! 0x20; every command that needs the GPU refuses by its type and stays
//! pending, so no GPU work is retired and no completion is fabricated.

use super::super::asc::{Firmware, Message as Mail};
use super::super::rtkit::{Endpoint, RtKit};
use super::channel;
use super::event;
use super::generation::{Family, Layout};
use super::initdata::{self, Root};
use super::ring::{self, Kind, Shared};
use super::signal;
use super::uat;
use crate::platform::dma::Port;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
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
/// The firmware-control doorbell's low byte that names the device-control
/// ring (index 4, kind 1).
const FWCTL_DEVICE_CONTROL: u64 = 0x11;
/// The device-control power-transition notice (`AGXAccelerator::
/// powerStateDidChangeTo`/`WillChangeTo` 0x1af8508/0x1af861c).
const DEVICE_CONTROL_POWER: u32 = 0x28;
/// The device-control types the firmware counts once handled, one bit per
/// type (its byte table at 0xffffff80000593a0, read at 0xffffff8000003a2c).
const COUNTED_DEVICE_CONTROL: u64 = 0x1fff_3bfb_f3c7_bffe;
/// The ring directory's firmware VA of the HWDSID table (handlers
/// 0xffffff80000043a0 and 0xffffff8000003ba4).
const DSID_TABLE: u64 = 0x2c8;
/// The data masters the kext keeps a histogram for: TA, 3D and CL, whose
/// 0x30-byte histograms follow the enables byte.
const HISTOGRAM_MASTERS: u32 = 3;
/// Bytes of the power-counter sample buffer.
const POWER_COUNTER_BYTES: usize = 0x1800;
/// The timed-out word of an `AGXLateEvalWait`'s firmware object
/// (handler 0xffffff8000003d34).
const LATE_EVAL_TIMED_OUT: u64 = 0x38;
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

/// A device-control command the model carries out, by its shared effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Power(PowerNotice),
    /// The firmware has no handler for the type, or keeps every effect in
    /// its own data or registers: nothing the AP shares changes.
    Private,
    /// 0xe: set a DSID's requested priority, release the DSID once the
    /// firmware's word matches it, then write `value` at `pointer`.
    DsidPriority {
        dsid: u8,
        priority: u32,
        pointer: u64,
        value: u32,
    },
    /// 0x14: clear a DSID's table slot, then write `value` at `pointer`.
    DsidDeprioritize {
        dsid: u8,
        pointer: u64,
        value: u32,
    },
    /// 0x1a operation 3 or 4: enable or disable a data master's histogram.
    Histogram {
        master: u32,
        enable: bool,
    },
    /// 0x27: mark a late-evaluation wait's firmware object timed out.
    LateEvalTimeout {
        wait: u64,
    },
    /// 0x32: empty the power-counter sample buffer.
    PowerCounters,
    /// 0x34/0x35: a RIART word in the root's +0x20 object.
    Riart {
        word: Riart,
        value: u32,
    },
}

/// The RIART words device control sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Riart {
    ULevelsDisabled,
    TDisabled,
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

// Every modeled interface's original firmware binds root+a8 to this 0x20-byte
// shared status object. Startup clears ready/generation, publishes powered,
// then publishes ready after native initialization (docs/research/agx.md).
const STATUS_POWERED: u64 = 0x10;
const STATUS_READY: u64 = 0x14;
const STATUS_GENERATION: u64 = 0x1c;
const STARTUP_STATUS: [(u64, u32); 4] = [
    (STATUS_READY, 0),
    (STATUS_GENERATION, 0),
    (STATUS_POWERED, 1),
    (STATUS_READY, 1),
];

/// One accepted signal command, including ordered effects and its exact
/// ring retirement. The owner survives every fallible DMA boundary.
#[derive(Debug)]
struct ActiveCommand {
    actions: Vec<signal::Action>,
    next: usize,
    publication: Option<event::Publication>,
    retirement: channel::Retirement,
}

impl ActiveCommand {
    /// GPU-work commands refuse by name here: only signal commands are
    /// accepted.
    fn accept(
        memory: &mut dyn Shared,
        command: channel::Command,
        retirement: channel::Retirement,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            actions: signal::prepare(memory, &command)?,
            next: 0,
            publication: None,
            retirement,
        })
    }

    fn advance(
        &mut self,
        memory: &mut dyn Shared,
        root: &Root,
        outbox: &mut Vec<Mail>,
        events: &mut u64,
    ) -> Result<bool, &'static str> {
        while let Some(&action) = self.actions.get(self.next) {
            match action {
                signal::Action::Event(event) => {
                    if self.publication.is_none() {
                        self.publication = event::Publication::reserve(memory, root, event)?;
                        if self.publication.is_none() {
                            return Ok(false);
                        }
                    }
                    self.publication.as_mut().unwrap().commit(memory)?;
                    self.publication = None;
                    outbox.push(Mail {
                        endpoint: MESSAGE_ENDPOINT,
                        payload: EVENT_TYPE << TYPE_SHIFT,
                    });
                    *events += 1;
                }
                write => write.write(memory)?,
            }
            self.next += 1;
        }
        self.retirement.commit(memory)?;
        Ok(true)
    }
}

/// A data-master entry retains the descriptor, channel and final read-index
/// publication until the channel's accepted commands have all completed.
#[derive(Debug)]
struct ActiveWork {
    descriptor: ring::Descriptor,
    next_read: u32,
    channel_state: u64,
    submission: channel::Submission,
    command: Option<ActiveCommand>,
    retiring: bool,
}

/// A RAM-only effect of an accepted device-control entry. Multi-page
/// buffers own their bytes through a partial-prefix fault; scalar stores
/// must satisfy the same single-page contract as signal publications.
#[derive(Debug)]
struct ControlWrite {
    address: u64,
    bytes: Vec<u8>,
}

impl ControlWrite {
    fn new(address: u64, bytes: &[u8]) -> Result<Self, &'static str> {
        address
            .checked_add(bytes.len() as u64 - 1)
            .ok_or("GFX device-control output range wraps")?;
        if bytes.len() <= 8 {
            ring::scalar_range(address, bytes.len() as u64)?;
        }
        Ok(Self {
            address,
            bytes: bytes.to_vec(),
        })
    }
}

/// The entry, read-derived values and exact retirement stay accepted until
/// all effects commit. Local notice/counter effects have their own phase so
/// a final consumer-index fault cannot count or enqueue them twice.
#[derive(Debug)]
struct ActiveControl {
    descriptor: ring::Descriptor,
    next_read: u32,
    kind: u32,
    power: Option<PowerNotice>,
    dsid_priority: Option<ControlPriority>,
    writes: Vec<ControlWrite>,
    count: Option<ControlCount>,
    next: usize,
    local_committed: bool,
}

/// Preserve the original priority store -> matching-word read -> optional
/// clear. A read fault observes the already committed priority store; a
/// later clear/write fault never repeats that store or rediscovers the match.
#[derive(Debug)]
struct ControlPriority {
    slot: u64,
    priority: u32,
    matched: Option<u32>,
    phase: u8,
}
impl ControlPriority {
    fn commit(&mut self, memory: &mut dyn Shared) -> Result<(), &'static str> {
        if self.phase == 0 {
            memory.write(self.slot, &self.priority.to_le_bytes())?;
            self.phase = 1;
        }
        if self.phase == 1 {
            self.matched = Some(memory.read_u32(self.slot + 4)?);
            self.phase = 2;
        }
        if self.phase == 2 {
            if self.matched == Some(self.priority) && self.priority != 0 {
                memory.write(self.slot, &[0; 8])?;
            }
            self.phase = 3;
        }
        Ok(())
    }
}

/// The original common-tail RMW follows the command's writes. Capture its
/// result before attempting the write, so a write fault never increments
/// twice; a read fault leaves prior command effects committed and owned.
#[derive(Debug)]
struct ControlCount {
    address: u64,
    value: Option<u32>,
    committed: bool,
}

impl ControlCount {
    fn commit(&mut self, memory: &mut dyn Shared) -> Result<(), &'static str> {
        if self.committed {
            return Ok(());
        }
        let value = match self.value {
            Some(value) => value,
            None => {
                let value = memory.read_u32(self.address)?.wrapping_add(1);
                self.value = Some(value);
                value
            }
        };
        memory.write(self.address, &value.to_le_bytes())?;
        self.committed = true;
        Ok(())
    }
}

impl ActiveControl {
    fn accept(
        memory: &mut dyn Shared,
        root: &Root,
        layout: &Layout,
        descriptor: ring::Descriptor,
        read: u32,
        entry: &[u8],
    ) -> Result<Self, &'static str> {
        let kind = u32::from_le_bytes(entry[..4].try_into().unwrap());
        let mut writes = Vec::new();
        let mut power = None;
        let mut dsid_priority = None;
        let mut put = |address: u64, bytes: &[u8]| -> Result<(), &'static str> {
            writes.push(ControlWrite::new(address, bytes)?);
            Ok(())
        };
        let address = |base: u64, offset: u64| {
            base.checked_add(offset)
                .ok_or("GFX device-control output address wraps")
        };
        match device_control_entry(entry)? {
            Command::Power(notice) => power = Some(notice),
            Command::Private => {}
            Command::DsidPriority {
                dsid,
                priority,
                pointer,
                value,
            } => {
                let slot = dsid_slot(memory, root, layout, dsid)?;
                ring::scalar_range(slot, 8)?;
                dsid_priority = Some(ControlPriority {
                    slot,
                    priority,
                    matched: None,
                    phase: 0,
                });
                put(pointer, &value.to_le_bytes())?;
            }
            Command::DsidDeprioritize {
                dsid,
                pointer,
                value,
            } => {
                let slot = dsid_slot(memory, root, layout, dsid)?;
                put(slot, &[0; 8])?;
                put(pointer, &value.to_le_bytes())?;
            }
            Command::Histogram { master, enable } => {
                let at = address(root.rings, layout.histogram_enables)?;
                let mut enables = [0];
                memory.read(at, &mut enables)?;
                let bit = 1 << master;
                enables[0] = if enable {
                    enables[0] | bit
                } else {
                    enables[0] & !bit
                };
                put(at, &enables)?;
            }
            Command::LateEvalTimeout { wait } => {
                put(address(wait, LATE_EVAL_TIMED_OUT)?, &1u32.to_le_bytes())?;
            }
            Command::PowerCounters => {
                put(
                    address(root.object_928, layout.power_counters)?,
                    &[0; POWER_COUNTER_BYTES],
                )?;
                put(
                    address(root.object_928, layout.power_counter_samples)?,
                    &[0; 4],
                )?;
            }
            Command::Riart { word, value } => {
                let offset = match word {
                    Riart::ULevelsDisabled => layout.riart_u_levels_disabled,
                    Riart::TDisabled => layout.riart_t_disabled,
                };
                put(address(root.object_358, offset)?, &value.to_le_bytes())?;
            }
        }
        let count = if COUNTED_DEVICE_CONTROL
            .checked_shr(kind)
            .is_some_and(|bits| bits & 1 != 0)
        {
            let address = address(root.object_928, layout.device_control_count)?;
            ring::scalar_range(address, 4)?;
            Some(ControlCount {
                address,
                value: None,
                committed: false,
            })
        } else {
            None
        };
        ring::scalar_range(descriptor.state, 4)?;
        Ok(Self {
            descriptor,
            next_read: ring::next(read),
            kind,
            power,
            dsid_priority,
            writes,
            count,
            next: 0,
            local_committed: false,
        })
    }
}

/// The GFX firmware protocol state shared by its two endpoints.
#[derive(Debug)]
pub struct State {
    /// The AGX family whose kext and firmware fix the interface.
    family: &'static Family,
    /// The firmware VA of the initdata root, once the kext sends it, as the
    /// 44-bit field of the message.
    pub initdata_va: Option<u64>,
    /// The root was validated through the UAT and startup status committed.
    pub initdata_checked: bool,
    /// The validated root, retained even if startup-status DMA later faults.
    pub root: Option<Root>,
    startup_word: usize,
    /// Work doorbells received, in order, as (pipe, submission index).
    pub work: Vec<(Pipe, u8)>,
    /// Count of device-control doorbells received.
    pub fwctl: u64,
    /// Power-transition notices consumed, in order.
    pub power: Vec<PowerNotice>,
    /// Device-control entries consumed, by type.
    pub device_control: BTreeMap<u32, u64>,
    /// Channel commands completed.
    pub commands: u64,
    /// Firmware events posted.
    pub events: u64,
    jobs: VecDeque<Job>,
    active_work: Option<ActiveWork>,
    active_control: Option<ActiveControl>,
}

impl State {
    /// A fresh protocol state for `family`'s interface.
    fn new(family: &'static Family) -> Self {
        State {
            family,
            initdata_va: None,
            initdata_checked: false,
            root: None,
            startup_word: 0,
            work: Vec::new(),
            fwctl: 0,
            power: Vec::new(),
            device_control: BTreeMap::new(),
            commands: 0,
            events: 0,
            jobs: VecDeque::new(),
            active_work: None,
            active_control: None,
        }
    }

    fn init(&mut self, payload: u64) -> Result<(), &'static str> {
        if payload >> TYPE_SHIFT != MSG_INIT {
            return Err("AGX message endpoint models only the 0x81 initdata message");
        }
        if payload & !(MSG_INIT << TYPE_SHIFT | INIT_VA_BITS) != 0 {
            return Err("AGX initdata message has bits outside its 44-bit address field");
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
        let type_bits = (DOORBELL_FLAG | TYPE_MASK) << TYPE_SHIFT;
        if payload & !(type_bits | 0x1f) != 0 {
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
        (self.initdata_va.is_some() && !self.initdata_checked)
            || !self.jobs.is_empty()
            || self.active_work.is_some()
            || self.active_control.is_some()
    }

    /// Read the root, then run the queued doorbells in order.
    fn dma(&mut self, memory: &mut dyn Shared, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        if let Some(va) = self.initdata_va.filter(|_| !self.initdata_checked) {
            if self.root.is_none() {
                let magic = self
                    .family
                    .initdata_magic
                    .ok_or("the GPU family's initdata root magic is not recovered")?;
                self.root = Some(Root::read(memory, uat::canonical_firmware_va(va), magic)?);
            }
            let status = self
                .root
                .as_ref()
                .expect("validated initdata root")
                .object_848;
            status
                .checked_add(0x20)
                .ok_or("GFX firmware status range wraps")?;
            while let Some(&(offset, value)) = STARTUP_STATUS.get(self.startup_word) {
                memory.write(status + offset, &value.to_le_bytes())?;
                self.startup_word += 1;
            }
            self.initdata_checked = true;
        }
        while let Some(&job) = self.jobs.front() {
            let root = self
                .root
                .clone()
                .ok_or("GFX doorbell before the initdata root")?;
            let complete = match job {
                Job::DeviceControl => {
                    self.device_control(memory, &root)?;
                    true
                }
                Job::Work(pipe, index) => self.work_ring(memory, &root, pipe, index, outbox)?,
            };
            if !complete {
                return Ok(());
            }
            self.jobs.pop_front();
        }
        Ok(())
    }

    /// Consume the device-control ring up to its write index.
    fn device_control(&mut self, memory: &mut dyn Shared, root: &Root) -> Result<(), &'static str> {
        let layout: &Layout = &self.family.model()?.layout;
        loop {
            if self.active_control.is_none() {
                let descriptor = root.device_control(memory)?;
                let (read, write) = descriptor.indices(memory)?;
                if read == write {
                    return Ok(());
                }
                let entry = descriptor.entry(memory, Kind::DeviceControl, read)?;
                self.active_control = Some(ActiveControl::accept(
                    memory, root, layout, descriptor, read, &entry,
                )?);
            }
            let active = self.active_control.as_mut().unwrap();
            if let Some(priority) = active.dsid_priority.as_mut() {
                priority.commit(memory)?;
            }
            while let Some(write) = active.writes.get(active.next) {
                memory.write(write.address, &write.bytes)?;
                active.next += 1;
            }
            if let Some(count) = active.count.as_mut() {
                count.commit(memory)?;
            }
            if !active.local_committed {
                if let Some(notice) = active.power {
                    self.power.push(notice);
                }
                *self.device_control.entry(active.kind).or_default() += 1;
                active.local_committed = true;
            }
            active.descriptor.retire(memory, active.next_read)?;
            self.active_control = None;
        }
    }

    /// Run a data-master ring's pending entries. Each names a channel; the
    /// channel's pending commands run in order, each retired from the
    /// channel's command ring once complete, and the entry is retired once
    /// the entry's captured command tail is reached. A command the model does not execute
    /// refuses by name and stays pending, as does its entry.
    fn work_ring(
        &mut self,
        memory: &mut dyn Shared,
        root: &Root,
        pipe: Pipe,
        index: u8,
        outbox: &mut Vec<Mail>,
    ) -> Result<bool, &'static str> {
        loop {
            if self.active_work.is_none() {
                let descriptor = root.work(memory, pipe, index)?;
                let (read, write) = descriptor.indices(memory)?;
                if read == write {
                    return Ok(true);
                }
                let entry = descriptor.entry(memory, Kind::DataMaster, read)?;
                let command = u32::from_le_bytes(entry[0x10..0x14].try_into().unwrap());
                if command != pipe as u32 {
                    return Err("GFX data-master entry's command type is not its ring's pipe");
                }
                let channel_state = u64::from_le_bytes(entry[0x08..0x10].try_into().unwrap());
                let queue = channel::Queue::read(memory, channel_state)?;
                let target = u16::from_le_bytes(entry[0x14..0x16].try_into().unwrap());
                let submission = queue.submission(memory, channel_state, target)?;
                ring::scalar_range(descriptor.state + ring::READ, 4)?;
                self.active_work = Some(ActiveWork {
                    descriptor,
                    next_read: ring::next(read),
                    channel_state,
                    submission,
                    command: None,
                    retiring: false,
                });
            }
            if self.active_work.as_ref().unwrap().retiring {
                let active = self.active_work.as_ref().unwrap();
                active.descriptor.retire(memory, active.next_read)?;
                self.active_work = None;
                continue;
            }
            self.active_work
                .as_mut()
                .unwrap()
                .submission
                .publish(memory)?;
            loop {
                let active = self.active_work.as_ref().unwrap();
                if active.command.is_none() {
                    let Some(va) = active.submission.next(memory)? else {
                        // The target is retained even if this final DMA
                        // fails. It cannot retire a later entry on retry.
                        self.active_work.as_mut().unwrap().retiring = true;
                        break;
                    };
                    let command = channel::Command::read(memory, va)?;
                    if command.kind == channel::Kind::DashboardSignal
                        && !self.family.dashboard_signals
                    {
                        return Err(
                            "GFX dashboard signal command: this GPU family's firmware has no dashboard-signal handler",
                        );
                    }
                    let retirement = active.submission.retirement();
                    self.active_work.as_mut().unwrap().command =
                        Some(ActiveCommand::accept(memory, command, retirement)?);
                }
                let active = self.active_work.as_mut().unwrap();
                if !active.command.as_mut().unwrap().advance(
                    memory,
                    root,
                    outbox,
                    &mut self.events,
                )? {
                    return Ok(false);
                }
                active.command = None;
                active.submission.consumed();
                self.commands += 1;
            }
        }
    }
}

/// The HWDSID table slot of `dsid`, through the ring directory's table VA.
fn dsid_slot(
    memory: &mut dyn Shared,
    root: &Root,
    layout: &Layout,
    dsid: u8,
) -> Result<u64, &'static str> {
    let pointer = root
        .rings
        .checked_add(DSID_TABLE)
        .ok_or("GFX HWDSID table pointer wraps")?;
    pointer
        .checked_add(7)
        .ok_or("GFX HWDSID table pointer wraps")?;
    let table = memory.read_u64(pointer)?;
    if table == 0 {
        return Err("GFX ring directory names no HWDSID table");
    }
    let offset = u64::from(dsid)
        .checked_mul(layout.dsid_slot_bytes)
        .ok_or("GFX HWDSID table slot offset wraps")?;
    let slot = table
        .checked_add(offset)
        .ok_or("GFX HWDSID table slot wraps")?;
    let extent = layout
        .dsid_slot_bytes
        .checked_sub(1)
        .ok_or("GFX HWDSID table has zero-sized slots")?;
    slot.checked_add(extent)
        .ok_or("GFX HWDSID table slot extent wraps")?;
    Ok(slot)
}

/// Every byte of `entry` after the type and outside `fields`, each a
/// half-open (start, end) byte range, is zero.
fn only(entry: &[u8], fields: &[(usize, usize)]) -> bool {
    entry.iter().enumerate().skip(4).all(|(at, &b)| {
        b == 0
            || fields
                .iter()
                .any(|&(start, end)| (start..end).contains(&at))
    })
}

/// Decode one device-control entry (`AGFIAcceleratorDeviceControlEntry`,
/// 0x40 bytes, the type at +0) into its shared effects. Each type's fields
/// are those its 26A434 kext builder writes; every other byte is zero, as
/// the builders zero the entry first. The firmware handlers are the 26A434
/// dispatcher's (0xffffff8000003a1c, a jump table over types 4..0x3b at
/// 0xffffff8000004c48); docs/research/agx.md §2 tabulates both sides.
fn device_control_entry(entry: &[u8]) -> Result<Command, &'static str> {
    let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(entry[at..at + 8].try_into().unwrap());
    let form = |fields: &[(usize, usize)], beyond: &'static str| {
        if only(entry, fields) {
            Ok(Command::Private)
        } else {
            Err(beyond)
        }
    };
    let boolean = |beyond: &'static str| {
        if word(4) > 1 {
            Err("GFX device-control flag word is not 0 or 1")
        } else {
            form(&[(4, 8)], beyond)
        }
    };
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
        // The dispatcher has no handler for these: they go straight to its
        // common tail. 7 is the device-state query; no 26A434 firmware code
        // writes its report at +0xe82c of the root's +0xb0 object, so the
        // section mask stays as the AP left it. 0x23 (FW utilisation
        // monitor), 0x2d (LUD hints), 0x12 (VKSCDM reset), 0x11 (VKSCDM
        // distribution), 0x1c (GVDM mode) and 0x31 (AVMR) are likewise
        // unhandled by this firmware.
        0x7 | 0x12 | 0x23 | 0x2d => form(&[], "GFX device control has fields beyond its type"),
        0x11 => form(
            &[(4, 0x14)],
            "GFX VKSCDM distribution has fields beyond its state",
        ),
        0x1c => form(&[(4, 8)], "GFX GVDM mode has fields beyond its word"),
        0x31 => form(
            &[(4, 0xd)],
            "GFX AVMR control has fields beyond its overrides",
        ),
        // Handlers whose effects stay in the firmware's own data, its
        // power-management threads or its registers. 0xb/0xc/0xd wake the
        // power thread for new hot-spot offsets and DPE/PPT parameters; 0x15
        // and 0x30 copy initdata configuration (the UMA recall words the kext
        // wrote at +0xe1c of the root's +0x20 object) into firmware data; 0x22
        // copies the display power words at +0x988 of the same object; 0x1b
        // only cleans the firmware's cached SFE tier-3 and THM counts at
        // directory +0x47d/+0x475, which no unit of the model ever raises;
        // 0x33 issues the register-window instruction-cache invalidate, which
        // the model's GPU, holding no instruction cache, has nothing to act on.
        // The rest set firmware power, QoS and scheduling state: 0xa idle
        // power-off, 0xf/0x10 CDM distribution, 0x13 resource release, 0x16/
        // 0x17 default QoS, 0x18 FRG power nap, 0x19 GIFAF hint, 0x25 QoS
        // knob, 0x38 power-counter selection (the list the kext wrote at
        // +0xca34 of the root's +0xb0 object) and 0x3b remote IOP power,
        // whose handler reads its words and does nothing.
        0xb | 0xc | 0xd | 0x10 | 0x15 | 0x1b | 0x22 | 0x30 | 0x38 => {
            form(&[], "GFX device control has fields beyond its type")
        }
        0xa => boolean("GFX idle power-off has fields beyond its flag"),
        0xf => form(
            &[(4, 0x1c)],
            "GFX CDM distribution has fields beyond its state",
        ),
        0x13 => form(
            &[(8, 0x14)],
            "GFX resource release has fields beyond its slots",
        ),
        0x16 | 0x17 => form(&[(4, 0xc)], "GFX default QoS has fields beyond its value"),
        0x18 => {
            if word(4) > 1 {
                return Err("GFX FRG power nap flag is not 0 or 1");
            }
            form(
                &[(4, 0x10)],
                "GFX FRG power nap has fields beyond its words",
            )
        }
        0x19 => boolean("GFX GIFAF streaming hint has fields beyond its flag"),
        0x25 => {
            // The firmware aborts on a data master other than 0..2
            // (0xffffff8000004c28).
            if entry[4] > 2 {
                return Err("GFX QoS knob names no data master the firmware accepts");
            }
            form(&[(4, 0xa)], "GFX QoS knob has fields beyond its knobs")
        }
        0x33 => form(
            &[(4, 0xc)],
            "GFX ICache invalidate has fields beyond its words",
        ),
        0x3b => form(
            &[(4, 0x10)],
            "GFX remote IOP power notice has fields beyond its words",
        ),
        // Handlers with shared effects.
        0xe => {
            if !only(entry, &[(4, 0x15)]) {
                return Err("GFX DSID priority has fields beyond its slot");
            }
            if u64_at(4) == 0 {
                return Err("GFX DSID priority names no completion word");
            }
            Ok(Command::DsidPriority {
                dsid: entry[0x14],
                priority: word(0x10),
                pointer: u64_at(4),
                value: word(0xc),
            })
        }
        0x14 => {
            if !only(entry, &[(4, 0x10), (0x14, 0x15)]) {
                return Err("GFX DSID deprioritize has fields beyond its slot");
            }
            if u64_at(4) == 0 {
                return Err("GFX DSID deprioritize names no completion word");
            }
            Ok(Command::DsidDeprioritize {
                dsid: entry[0x14],
                pointer: u64_at(4),
                value: word(0xc),
            })
        }
        0x1a => {
            if !only(entry, &[(4, 9)]) {
                return Err("GFX context-switch histogram has fields beyond its operation");
            }
            let master = word(4);
            if master >= HISTOGRAM_MASTERS {
                return Err("GFX context-switch histogram names no data master");
            }
            match entry[8] {
                // 1 (get), 2 (reset) and 5 only clean the firmware's cached
                // histogram for the AP to read; the model never switches a
                // data master's context, so its bins stay as they are.
                1 | 2 | 5 => Ok(Command::Private),
                3 => Ok(Command::Histogram {
                    master,
                    enable: true,
                }),
                4 => Ok(Command::Histogram {
                    master,
                    enable: false,
                }),
                _ => Err("GFX context-switch histogram names no operation"),
            }
        }
        0x27 => {
            if !only(entry, &[(4, 0x20)]) {
                return Err("GFX late-eval timeout has fields beyond its wait");
            }
            match u64_at(4) {
                0 => Err("GFX late-eval timeout names no wait"),
                wait => Ok(Command::LateEvalTimeout { wait }),
            }
        }
        0x32 => {
            form(&[], "GFX power-counter gather has fields beyond its type")?;
            Ok(Command::PowerCounters)
        }
        0x34 => {
            form(
                &[(4, 8)],
                "GFX RIART U-level mask has fields beyond its word",
            )?;
            Ok(Command::Riart {
                word: Riart::ULevelsDisabled,
                value: word(4),
            })
        }
        0x35 => {
            boolean("GFX RIART T-disable has fields beyond its flag")?;
            Ok(Command::Riart {
                word: Riart::TDisabled,
                value: word(4),
            })
        }
        // Refused by name.
        0x4 | 0x5 => Err(
            "GFX device control 0x4/0x5 starts or stops performance-counter sampling, which programs counter hardware the model lacks",
        ),
        // AGXAccelerator::allocateMemoryEvent answers a host-allocation
        // request the firmware raised; the model raises none.
        0x8 | 0x26 => Err(
            "GFX device control 0x8/0x26 answers a firmware host-allocation request the model never makes",
        ),
        0x9 => Err(
            "GFX device control 0x9 answers a firmware event the model never posts and wakes a firmware scheduler thread it does not run",
        ),
        0x1f => Err(
            "GFX device control 0x1f updates an app role in the firmware scheduler's context registry, which the model does not keep",
        ),
        // An AFR perf-state override the 26A434 firmware lacks: its handler
        // only logs a warning, and firmware log records are excluded
        // (docs/research/agx.md §5.7), so the entry is consumed.
        0x24 => form(&[(4, 8)], "GFX AFR perf state has fields beyond its word"),
        0x29 => Err(
            "GFX device control 0x29 hands an exiting context to a firmware teardown thread the model does not run",
        ),
        0x2c => Err(
            "GFX device control 0x2c (external CS or kill request) is a fatal unsupported command in the 26A434 firmware",
        ),
        _ => Err("GFX device-control type is not one the 26A434 kext sends"),
    }
}

/// A handle to the shared protocol state, for the DMA boundary and tests.
#[derive(Clone)]
pub struct Protocol(Rc<RefCell<State>>);

impl Protocol {
    /// The protocol of `family`'s firmware.
    pub fn new(family: &'static Family) -> Self {
        Protocol(Rc::new(RefCell::new(State::new(family))))
    }

    pub fn with<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.0.borrow())
    }
}

/// The GFX coprocessor: RTKit with the GFX endpoints and the firmware's DMA.
pub struct Coprocessor {
    rtkit: RtKit,
    protocol: Protocol,
    power: Option<super::sgx::FirmwarePower>,
}

impl Coprocessor {
    /// `family`'s GFX coprocessor, whose RTKit manages its power ordinarily
    /// (`power-managed`).
    pub fn new(family: &'static Family) -> Result<Self, &'static str> {
        let (endpoints, protocol) = endpoints(family);
        let rtkit = RtKit::new(endpoints, super::super::rtkit::Management::Ordinary)?;
        Ok(Self {
            rtkit,
            protocol,
            power: None,
        })
    }

    /// Attach the native power/register owner of the mounted SGX instance.
    /// A qualified physical binding does not make unknown callbacks successful.
    pub fn with_power(
        family: &'static Family,
        power: super::sgx::FirmwarePower,
    ) -> Result<Self, &'static str> {
        if family != power.family() {
            return Err("GFX firmware power owner belongs to a different GPU family");
        }
        let mut coprocessor = Self::new(family)?;
        coprocessor.power = Some(power);
        Ok(coprocessor)
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

impl Firmware for Coprocessor {
    fn check_reset(&self) -> Result<(), &'static str> {
        if let Some(power) = &self.power {
            power.check_reset()?;
        }
        self.rtkit.check_reset()
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.check_reset()?;
        self.rtkit.reset()
    }
    fn start(&mut self, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        self.rtkit.start(outbox)
    }
    fn receive(&mut self, message: Mail, outbox: &mut Vec<Mail>) -> Result<(), &'static str> {
        if message.endpoint == 0
            && message.payload >> 52 & 0xf == 6
            && matches!(message.payload & !(0xf << 52), 0x201 | 0x202 | 0)
        {
            if self.protocol.with(State::dma_pending) {
                return Err("GFX IOP sleep with owned initdata or queued channel work");
            }
            if self.protocol.with(|state| state.initdata_va.is_some()) {
                // Original native power callbacks depend on the AP hardware
                // config, update shared powered/generation words and restore
                // GPU registers. A bare management ACK cannot stand for them.
                return Err(if self.power.is_some() {
                    "GFX initialized IOP sleep requires complete config-derived native callbacks"
                } else {
                    "GFX initialized IOP sleep requires native power callbacks and GPU restore semantics"
                });
            }
        }
        if matches!(message.endpoint, MESSAGE_ENDPOINT | DOORBELL_ENDPOINT)
            && !matches!(
                self.rtkit.iop_power(),
                super::super::rtkit::POWER_ON | 0x220
            )
        {
            return Err("GFX application message while the IOP is not awake");
        }
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
    fn check_reset(&self) -> Result<(), &'static str> {
        if self.0.with(State::dma_pending) {
            return Err("GFX physical reset with owned initdata or queued channel work");
        }
        Ok(())
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        self.check_reset()?;
        let mut state = self.0.0.borrow_mut();
        state.initdata_va = None;
        state.initdata_checked = false;
        state.root = None;
        state.startup_word = 0;
        // Historical counters/journals remain diagnostic evidence. Channel
        // addresses and validation are cold-reset session state.
        Ok(())
    }
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.0.borrow_mut().init(payload)
    }
}

impl Endpoint for Doorbell {
    fn check_reset(&self) -> Result<(), &'static str> {
        Message(self.0.clone()).check_reset()
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        Message(self.0.clone()).reset()
    }
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(&mut self, payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.0.0.borrow_mut().doorbell(payload)
    }
}

/// The GFX coprocessor's application endpoints and a handle to their shared
/// state. Pass the endpoints to [`super::super::rtkit::RtKit::new`].
pub fn endpoints(family: &'static Family) -> (Vec<NumberedEndpoint>, Protocol) {
    let protocol = Protocol::new(family);
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
    use crate::platform::apple::agx::generation::{G13G, G13X, G14G, G14X, G15G, MAGIC_G13_G14G};
    use crate::platform::apple::agx::initdata::tests::{BASE, RINGS, ROOT, kext_root};
    use crate::platform::apple::agx::ring::tests::Flat;
    use crate::platform::apple::agx::ring::{READ, WRITE};
    use core::ops::Range;

    fn doorbell_payload(kind: u64, low: u64) -> u64 {
        ((DOORBELL_FLAG | kind) << TYPE_SHIFT) | low
    }

    fn work(pipe: u64, index: u64) -> u64 {
        doorbell_payload(DOORBELL_WORK, (index & 7) << 2 | pipe)
    }

    fn booted_gfx(family: &'static Family) -> Coprocessor {
        let mut firmware = Coprocessor::new(family).unwrap();
        firmware.start(&mut Vec::new()).unwrap();
        for payload in [
            2 << 52 | 12 | 12 << 16,
            8 << 52,
            8 << 52 | 1 << 51 | 1 << 32,
        ] {
            firmware
                .receive(
                    Mail {
                        endpoint: 0,
                        payload,
                    },
                    &mut Vec::new(),
                )
                .unwrap();
        }
        for endpoint in [MESSAGE_ENDPOINT, DOORBELL_ENDPOINT] {
            firmware
                .receive(
                    Mail {
                        endpoint: 0,
                        payload: 5 << 52 | u64::from(endpoint) << 32 | 2,
                    },
                    &mut Vec::new(),
                )
                .unwrap();
        }
        firmware
    }

    #[test]
    fn native_power_constructor_keeps_the_concrete_family_and_callback_refusal() {
        use crate::platform::apple::agx::{generation::GPUS, sgx::Sgx};
        for family in [&G13G, &G13X, &G14G, &G14X] {
            let gpu = GPUS
                .iter()
                .find(|gpu| gpu.family == family && gpu.admitted().is_ok())
                .unwrap();
            let mut sgx = Sgx::new(gpu).unwrap();
            let power = sgx.firmware_power(&[(0x204000000, 0x4000000, 0)]).unwrap();
            let mut firmware = Coprocessor::with_power(family, power.clone()).unwrap();
            let other = if family == &G14G { &G13G } else { &G14G };
            assert!(Coprocessor::with_power(other, power.clone()).is_err());
            // A truthful target binding alone is not enough to acknowledge
            // unimplemented config-dependent callback effects.
            firmware.protocol.0.borrow_mut().initdata_va = Some(ROOT);
            let mut outbox = Vec::new();
            assert!(
                firmware
                    .receive(
                        Mail {
                            endpoint: 0,
                            payload: 6 << 52 | 0x201
                        },
                        &mut outbox
                    )
                    .unwrap_err()
                    .contains("owned initdata")
            );
            firmware.protocol.0.borrow_mut().initdata_checked = true;
            assert_eq!(
                firmware.receive(
                    Mail {
                        endpoint: 0,
                        payload: 6 << 52 | 0x201
                    },
                    &mut outbox
                ),
                Err("GFX initialized IOP sleep requires complete config-derived native callbacks")
            );
            assert!(outbox.is_empty());
            if family == &G13G || family == &G14G {
                use crate::platform::apple::bus::{Access, MmioDevice, Width};
                use crate::platform::apple::interrupt::InterruptLatch;
                let mut latch = InterruptLatch::new();
                let mut access = Access::new(0, 0, &mut latch);
                sgx.write(0xd04074, Width::Word, 1, &mut access).unwrap();
                assert!(firmware.reset().unwrap_err().contains("restore ownership"));
                assert_eq!(
                    firmware.protocol.with(|state| state.initdata_va),
                    Some(ROOT)
                );
                sgx.write(0xd04074, Width::Word, 0, &mut access).unwrap();
                sgx.write(0xd06020, Width::Word, 1, &mut access).unwrap();
                firmware.reset().unwrap();
                assert_eq!(firmware.protocol.with(|state| state.initdata_va), None);
            }
        }
    }

    #[test]
    fn native_power_refusal_is_atomic_before_and_after_startup_for_every_modeled_family() {
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for sleep in [0, 0x201, 0x202] {
                let mut firmware = booted_gfx(family);
                let mut outbox = Vec::new();
                let power = |state| Mail {
                    endpoint: 0,
                    payload: 6 << 52 | state,
                };
                // Before initdata there are no registered native callbacks.
                firmware.receive(power(sleep), &mut outbox).unwrap();
                assert_eq!(
                    outbox,
                    [Mail {
                        endpoint: 0,
                        payload: 7 << 52 | sleep
                    }]
                );
                outbox.clear();
                for message in [
                    Mail {
                        endpoint: MESSAGE_ENDPOINT,
                        payload: MSG_INIT << TYPE_SHIFT | ROOT & INIT_VA_BITS,
                    },
                    Mail {
                        endpoint: DOORBELL_ENDPOINT,
                        payload: work(0, 0),
                    },
                ] {
                    assert_eq!(
                        firmware.receive(message, &mut outbox),
                        Err("GFX application message while the IOP is not awake")
                    );
                }
                assert!(!firmware.dma_pending());
                assert!(outbox.is_empty());
                firmware.receive(power(0x220), &mut outbox).unwrap();
                outbox.clear();
                let mut memory = Flat::new(BASE, 0x20000);
                kext_root(&mut memory);
                memory.put_u64(ROOT, family.initdata_magic.unwrap());
                firmware
                    .receive(
                        Mail {
                            endpoint: MESSAGE_ENDPOINT,
                            payload: MSG_INIT << TYPE_SHIFT | ROOT & INIT_VA_BITS,
                        },
                        &mut outbox,
                    )
                    .unwrap();
                for initialized in [false, true] {
                    if initialized {
                        firmware
                            .protocol
                            .0
                            .borrow_mut()
                            .dma(&mut memory, &mut outbox)
                            .unwrap();
                    }
                    let bytes = memory.bytes.clone();
                    assert!(firmware.receive(power(sleep), &mut outbox).is_err());
                    assert!(outbox.is_empty());
                    assert_eq!(firmware.rtkit.iop_power(), 0x220);
                    assert_eq!(memory.bytes, bytes);
                    assert_eq!(firmware.dma_pending(), !initialized);
                    // A repeated wake has no native transition or generation.
                    firmware.receive(power(0x220), &mut outbox).unwrap();
                    assert_eq!(
                        outbox,
                        [Mail {
                            endpoint: 0,
                            payload: 7 << 52 | 0x220
                        }]
                    );
                    outbox.clear();
                    assert!(firmware.receive(power(0x10), &mut outbox).is_err());
                    assert!(outbox.is_empty());
                    assert_eq!(firmware.rtkit.iop_power(), 0x220);
                    assert_eq!(memory.bytes, bytes);
                }
            }
        }
    }

    const CONTROL_STATE: u64 = BASE + 0x8000;
    const CONTROL_ENTRIES: u64 = BASE + 0xa000;

    /// A checked root whose device-control ring holds `entries`.
    fn with_device_control(entries: &[[u8; 0x40]]) -> (State, Flat) {
        with_device_control_on(&G14G, entries).unwrap()
    }

    /// `family`'s firmware, having read the root, with `entries` on its
    /// device-control ring.
    fn with_device_control_on(
        family: &'static Family,
        entries: &[[u8; 0x40]],
    ) -> Result<(State, Flat), &'static str> {
        let mut memory = Flat::new(BASE, 0x20000);
        kext_root(&mut memory);
        if let Some(magic) = family.initdata_magic {
            memory.put_u64(ROOT, magic);
        }
        memory.put_descriptor(RINGS + 0x1a0, CONTROL_STATE, CONTROL_ENTRIES);
        for (n, entry) in entries.iter().enumerate() {
            memory.put(CONTROL_ENTRIES + n as u64 * 0x40, entry);
        }
        memory.put_u32(CONTROL_STATE + WRITE, entries.len() as u32);
        let mut state = State::new(family);
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        state.dma(&mut memory, &mut Vec::new())?;
        Ok((state, memory))
    }

    fn power(word: u32) -> [u8; 0x40] {
        let mut entry = [0; 0x40];
        entry[..4].copy_from_slice(&DEVICE_CONTROL_POWER.to_le_bytes());
        entry[4..8].copy_from_slice(&word.to_le_bytes());
        entry
    }

    /// Fail before a selected startup write; record only committed writes.
    struct StartupMemory {
        flat: Flat,
        fail_at: Option<usize>,
        writes: Vec<(u64, u32)>,
        reads: usize,
    }

    impl Shared for StartupMemory {
        fn read(&mut self, va: u64, data: &mut [u8]) -> Result<(), &'static str> {
            self.reads += 1;
            self.flat.read(va, data)
        }
        fn write(&mut self, va: u64, data: &[u8]) -> Result<(), &'static str> {
            if self.fail_at == Some(self.writes.len()) {
                return Err("startup status write fault");
            }
            self.flat.write(va, data)?;
            self.writes
                .push((va, u32::from_le_bytes(data.try_into().unwrap())));
            Ok(())
        }
        fn gpu_read(
            &mut self,
            context: usize,
            va: u64,
            data: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            self.flat.gpu_read(context, va, data)
        }
        fn gpu_write(
            &mut self,
            context: usize,
            va: u64,
            data: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            self.flat.gpu_write(context, va, data)
        }
    }

    #[test]
    fn cold_start_status_owns_each_committed_word_across_faults_for_every_modeled_family() {
        let status = BASE + 0x4000;
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for fault in 0..STARTUP_STATUS.len() {
                let mut flat = Flat::new(BASE, 0x20000);
                kext_root(&mut flat);
                flat.put_u64(ROOT, family.initdata_magic.unwrap());
                flat.put(status, &[0xa5; 0x20]);
                let mut memory = StartupMemory {
                    flat,
                    fail_at: Some(fault),
                    writes: Vec::new(),
                    reads: 0,
                };
                let protocol = Protocol(Rc::new(RefCell::new(State::new(family))));
                let mut endpoint = Message(protocol.clone());
                let mut outbox = Vec::new();
                endpoint
                    .receive(
                        MSG_INIT << TYPE_SHIFT | (ROOT & INIT_VA_BITS),
                        &mut Vec::new(),
                    )
                    .unwrap();
                assert_eq!(
                    protocol.0.borrow_mut().dma(&mut memory, &mut outbox),
                    Err("startup status write fault")
                );
                assert_eq!(memory.writes.len(), fault);
                assert!(outbox.is_empty());
                assert!(protocol.with(State::dma_pending));
                assert!(!protocol.with(|state| state.initdata_checked));
                assert!(endpoint.reset().is_err());
                // An accepted root and committed prefix survive repeated faults.
                let reads = memory.reads;
                memory.flat.put_u64(ROOT, 0);
                memory.flat.put_u64(ROOT + 0xa8, BASE + 0x8000);
                assert!(
                    protocol
                        .0
                        .borrow_mut()
                        .dma(&mut memory, &mut outbox)
                        .is_err()
                );
                assert_eq!(memory.reads, reads);
                assert_eq!(memory.writes.len(), fault);
                memory.fail_at = None;
                protocol
                    .0
                    .borrow_mut()
                    .dma(&mut memory, &mut outbox)
                    .unwrap();
                let expected = STARTUP_STATUS.map(|(offset, value)| (status + offset, value));
                assert_eq!(memory.writes, expected);
                assert_eq!(memory.reads, reads);
                assert!(outbox.is_empty());
                assert!(!protocol.with(State::dma_pending));
                assert!(protocol.with(|state| state.initdata_checked));
                assert_eq!(memory.flat.read_u32(status + STATUS_POWERED).unwrap(), 1);
                assert_eq!(memory.flat.read_u32(status + STATUS_READY).unwrap(), 1);
                assert_eq!(memory.flat.read_u32(status + STATUS_GENERATION).unwrap(), 0);
                let mut untouched = [0; 0x10];
                memory.flat.read(status, &mut untouched).unwrap();
                assert_eq!(untouched, [0xa5; 0x10]);
                assert_eq!(memory.flat.read_u32(status + 0x18).unwrap(), 0xa5a5_a5a5);
                // Idle cold-reset starts root validation and publication again.
                endpoint.reset().unwrap();
                endpoint
                    .receive(
                        MSG_INIT << TYPE_SHIFT | (ROOT & INIT_VA_BITS),
                        &mut Vec::new(),
                    )
                    .unwrap();
                assert_eq!(
                    protocol.0.borrow_mut().dma(&mut memory, &mut outbox),
                    Err("GFX initdata root lacks its magic")
                );
                assert_eq!(memory.writes, expected);
                kext_root(&mut memory.flat);
                memory.flat.put_u64(ROOT, family.initdata_magic.unwrap());
                protocol
                    .0
                    .borrow_mut()
                    .dma(&mut memory, &mut outbox)
                    .unwrap();
                assert_eq!(&memory.writes[4..], &expected);
            }
        }
    }

    #[test]
    fn physical_reset_preserves_unprocessed_channel_ownership() {
        let (state, mut memory) = with_device_control(&[power(0)]);
        let protocol = Protocol(Rc::new(RefCell::new(state)));
        let mut endpoint = Message(protocol.clone());
        protocol
            .0
            .borrow_mut()
            .doorbell((0x84 << TYPE_SHIFT) | 0x11)
            .unwrap();
        assert!(endpoint.check_reset().is_err());
        assert!(endpoint.reset().is_err());
        assert!(protocol.with(|state| state.initdata_checked));
        protocol
            .0
            .borrow_mut()
            .dma(&mut memory, &mut Vec::new())
            .unwrap();
        assert_eq!(protocol.with(|state| state.power.len()), 1);
        endpoint.check_reset().unwrap();
        endpoint.reset().unwrap();
        assert_eq!(protocol.with(|state| state.initdata_va), None);
        // History remains inspectable; a new initdata session is accepted.
        assert_eq!(protocol.with(|state| state.power.len()), 1);
        endpoint
            .receive(
                MSG_INIT << TYPE_SHIFT | (ROOT & INIT_VA_BITS),
                &mut Vec::new(),
            )
            .unwrap();
        assert!(protocol.with(State::dma_pending));
    }

    #[test]
    fn the_message_endpoint_captures_the_initdata_pointer_once() {
        let mut state = State::new(&G14G);
        let va = 0x4_1234_5000;
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_ok());
        assert_eq!(state.initdata_va, Some(va));
        // A second initdata, or any other message type, is refused.
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_err());
        let mut fresh = State::new(&G14G);
        assert!(fresh.init(0x42 << TYPE_SHIFT).is_err());
        // Reserved low bits are not another way to spell the same VA.
        for bit in 44..48 {
            let mut wide = State::new(&G14G);
            assert!(
                wide.init((MSG_INIT << TYPE_SHIFT) | INIT_VA_BITS | (1 << bit))
                    .is_err()
            );
            assert_eq!(wide.initdata_va, None);
            assert!(!wide.dma_pending());
        }
    }

    #[test]
    fn doorbells_take_the_kexts_forms_and_queue_firmware_work() {
        let (endpoints, protocol) = endpoints(&G14G);
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
        let mut state = State::new(&G14G);
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
    fn every_reserved_doorbell_bit_refuses_without_queueing_or_counting_work() {
        // kickFirmware masks the type to six bits, fixes bit 55, and uses
        // only bits 4:0 for index/pipe. In particular bit 54 is reserved,
        // even though simply masking to the type would accept 0xc3/0xc4.
        let allowed = (DOORBELL_FLAG | TYPE_MASK) << TYPE_SHIFT | 0x1f;
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for bit in 0..64 {
                if allowed & (1 << bit) != 0 {
                    continue;
                }
                let mut state = State::new(family);
                for payload in [work(2, 3), doorbell_payload(DOORBELL_FWCTL, 0x11)] {
                    assert!(state.doorbell(payload | 1 << bit).is_err());
                    assert!(state.work.is_empty());
                    assert_eq!(state.fwctl, 0);
                    assert!(state.jobs.is_empty());
                }
                // A rejected message must leave the endpoint usable.
                state.doorbell(work(2, 3)).unwrap();
                assert_eq!(state.work, [(Pipe::Compute, 3)]);
                assert_eq!(state.jobs.len(), 1);
            }
        }
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

    const OBJECT_928: u64 = BASE + 0x5000;
    const OBJECT_358: u64 = BASE + 0x3000;

    /// The G14G interface, which the tests' root carries.
    fn layout() -> &'static Layout {
        &G14G.model().unwrap().layout
    }

    /// The handled-entry count.
    fn count() -> u64 {
        OBJECT_928 + layout().device_control_count
    }

    /// A device-control entry of `kind` whose bytes in `fields` are `fill`.
    fn filled(kind: u32, fields: Range<usize>, fill: u8) -> [u8; 0x40] {
        let mut entry = [0; 0x40];
        entry[..4].copy_from_slice(&kind.to_le_bytes());
        entry[fields].fill(fill);
        entry
    }

    fn of_type(kind: u32) -> [u8; 0x40] {
        filled(kind, 4..4, 0)
    }

    /// Ring the device-control doorbell and run the firmware's DMA.
    fn ring(state: &mut State, memory: &mut Flat) -> Result<(), &'static str> {
        state.doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))?;
        state.dma(memory, &mut Vec::new())
    }

    #[test]
    fn the_device_state_query_leaves_the_report_as_the_ap_left_it() {
        let (mut state, mut memory) = with_device_control(&[of_type(7)]);
        // A mask the AP left; the 26A434 firmware has no type-7 handler.
        let sections = OBJECT_928 + 0xe82c;
        memory.put(sections, &[1]);
        ring(&mut state, &mut memory).unwrap();
        let mut mask = [0xff];
        memory.read(sections, &mut mask).unwrap();
        assert_eq!(mask, [1]);
        assert_eq!(state.device_control.get(&7), Some(&1));
        assert_eq!(memory.read_u32(count()), Ok(1));
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(1));
        assert!(device_control_entry(&filled(7, 8..9, 1)).is_err());
    }

    #[test]
    fn the_configuration_snapshot_is_taken_and_left_uncounted() {
        let snapshot = of_type(0x15);
        let (mut state, mut memory) = with_device_control(&[power(0), snapshot, power(1)]);
        memory.put_u32(count(), 7);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(state.device_control.get(&0x15), Some(&1));
        // The two power notices are counted; the snapshot is not.
        assert_eq!(memory.read_u32(count()), Ok(9));
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(3));
        assert!(device_control_entry(&filled(0x15, 4..5, 1)).is_err());
    }

    /// Every kext form whose firmware handler changes nothing the AP shares.
    fn private_forms() -> Vec<[u8; 0x40]> {
        let mut forms: Vec<_> = [
            0x7, 0x12, 0x23, 0x2d, 0xb, 0xc, 0xd, 0x10, 0x15, 0x1b, 0x22, 0x30, 0x38,
        ]
        .into_iter()
        .map(of_type)
        .collect();
        forms.extend([
            filled(0x11, 4..0x14, 0x5a),
            filled(0x1c, 4..8, 0x5a),
            filled(0x31, 4..0xd, 0x5a),
            filled(0xa, 4..5, 1),
            filled(0xf, 4..0x1c, 0x5a),
            filled(0x13, 8..0x14, 0x5a),
            filled(0x16, 4..0xc, 0x5a),
            filled(0x17, 4..0xc, 0x5a),
            filled(0x18, 8..0x10, 0x5a),
            filled(0x19, 4..5, 1),
            filled(0x24, 4..8, 0x5a),
            filled(0x25, 4..0xa, 2),
            filled(0x33, 4..0xc, 0x5a),
            filled(0x3b, 4..0x10, 0x5a),
        ]);
        forms
    }

    #[test]
    fn private_device_control_is_consumed_and_counted_by_the_firmware_table() {
        let forms = private_forms();
        let (mut state, mut memory) = with_device_control(&forms);
        let before = memory.bytes.clone();
        ring(&mut state, &mut memory).unwrap();
        let entries = forms.len() as u32;
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(entries));
        // 0x13, 0x15, 0x1b and 0x22 are the uncounted ones among them.
        assert_eq!(memory.read_u32(count()), Ok(entries - 4));
        assert_eq!(
            state.device_control.values().sum::<u64>(),
            u64::from(entries)
        );
        // Nothing else the AP shares changed.
        let mut after = memory.bytes.clone();
        for at in [CONTROL_STATE + READ, count()] {
            let at = (at - BASE) as usize;
            after[at..at + 4].copy_from_slice(&before[at..at + 4]);
        }
        assert!(after == before);
    }

    #[test]
    fn private_device_control_refuses_bytes_outside_its_form() {
        for form in private_forms() {
            let mut extra = form;
            extra[0x3f] = 1;
            assert!(device_control_entry(&extra).is_err());
        }
        // Flags are 0 or 1, and the QoS knob's data master is 0..2.
        assert!(device_control_entry(&filled(0xa, 4..5, 2)).is_err());
        assert!(device_control_entry(&filled(0x18, 4..5, 2)).is_err());
        assert!(device_control_entry(&filled(0x25, 4..5, 3)).is_err());
    }

    /// A HWDSID table named by the ring directory, and an entry of `kind`
    /// for DSID 3 whose completion word is at `word` with value 0x700.
    fn dsid_entry(memory: &mut Flat, kind: u32, word: u64) -> ([u8; 0x40], u64) {
        let table = BASE + 0x1e000;
        memory.put_u64(RINGS + DSID_TABLE, table);
        let mut entry = of_type(kind);
        entry[4..0xc].copy_from_slice(&word.to_le_bytes());
        entry[0xc..0x10].copy_from_slice(&0x700u32.to_le_bytes());
        entry[0x14] = 3;
        (entry, table + 3 * layout().dsid_slot_bytes)
    }

    #[test]
    fn dsid_priority_sets_the_table_and_releases_a_matched_slot() {
        let (mut state, mut memory) = with_device_control(&[]);
        let word = BASE + 0x1f000;
        let (mut entry, slot) = dsid_entry(&mut memory, 0xe, word);
        entry[0x10..0x14].copy_from_slice(&5u32.to_le_bytes());
        // The firmware's word does not match yet: the request stays.
        memory.put(CONTROL_ENTRIES, &entry);
        memory.put_u32(slot + 4, 4);
        memory.put_u32(CONTROL_STATE + WRITE, 1);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u32(slot), Ok(5));
        assert_eq!(memory.read_u32(slot + 4), Ok(4));
        assert_eq!(memory.read_u32(word), Ok(0x700));
        // A matching word releases the slot.
        memory.put(CONTROL_ENTRIES + 0x40, &entry);
        memory.put_u32(slot + 4, 5);
        memory.put_u32(word, 0);
        memory.put_u32(CONTROL_STATE + WRITE, 2);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u64(slot), Ok(0));
        assert_eq!(memory.read_u32(word), Ok(0x700));
        // 0xe is uncounted.
        assert_eq!(memory.read_u32(count()), Ok(0));
        assert_eq!(state.device_control.get(&0xe), Some(&2));
        entry[0x15] = 1;
        assert!(device_control_entry(&entry).is_err());
        entry[0x15] = 0;
        entry[4..0xc].fill(0);
        assert!(device_control_entry(&entry).is_err());
    }

    #[test]
    fn dsid_deprioritize_clears_the_slot_and_writes_the_completion_word() {
        let (mut state, mut memory) = with_device_control(&[]);
        let word = BASE + 0x1f000;
        let (mut entry, slot) = dsid_entry(&mut memory, 0x14, word);
        memory.put(CONTROL_ENTRIES, &entry);
        memory.put_u64(slot, 0x0000_0006_0000_0006);
        memory.put_u32(CONTROL_STATE + WRITE, 1);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u64(slot), Ok(0));
        assert_eq!(memory.read_u32(word), Ok(0x700));
        assert_eq!(memory.read_u32(count()), Ok(0));
        // The kext leaves +0x10..+0x14 zero.
        entry[0x10] = 1;
        assert!(device_control_entry(&entry).is_err());
        // Without a table the entry refuses and stays.
        let (mut bare, mut memory) = with_device_control(&[]);
        entry[0x10] = 0;
        memory.put(CONTROL_ENTRIES, &entry);
        memory.put_u32(CONTROL_STATE + WRITE, 1);
        assert_eq!(
            ring(&mut bare, &mut memory),
            Err("GFX ring directory names no HWDSID table")
        );
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(0));
    }

    #[test]
    fn the_context_switch_histogram_family_follows_the_firmware() {
        // The boot run's entry: get (1) for data master 0.
        let get = filled(0x1a, 8..9, 1);
        let mut enable = filled(0x1a, 8..9, 3);
        enable[4] = 2;
        let mut disable = filled(0x1a, 8..9, 4);
        disable[4] = 1;
        let reset = filled(0x1a, 8..9, 2);
        let (mut state, mut memory) = with_device_control(&[get, enable, disable, reset]);
        let enables = RINGS + layout().histogram_enables;
        memory.put(enables, &[0b011]);
        // A bin the AP reads back after the get.
        memory.put_u32(enables + 1, 9);
        ring(&mut state, &mut memory).unwrap();
        let mut bits = [0];
        memory.read(enables, &mut bits).unwrap();
        assert_eq!(bits, [0b101]);
        assert_eq!(memory.read_u32(enables + 1), Ok(9));
        assert_eq!(state.device_control.get(&0x1a), Some(&4));
        // 0x1a is uncounted.
        assert_eq!(memory.read_u32(count()), Ok(0));
        // No fourth data master, no operation 0, nothing beyond +8.
        let mut master = get;
        master[4] = 3;
        assert!(device_control_entry(&master).is_err());
        assert!(device_control_entry(&filled(0x1a, 8..9, 0)).is_err());
        assert!(device_control_entry(&filled(0x1a, 8..0xa, 1)).is_err());
    }

    #[test]
    fn a_late_eval_timeout_marks_its_wait() {
        let wait = BASE + 0x1f000;
        let mut entry = filled(0x27, 0xc..0x20, 0x5a);
        entry[4..0xc].copy_from_slice(&wait.to_le_bytes());
        let (mut state, mut memory) = with_device_control(&[entry]);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u32(wait + LATE_EVAL_TIMED_OUT), Ok(1));
        assert_eq!(memory.read_u32(count()), Ok(1));
        entry[0x20] = 1;
        assert!(device_control_entry(&entry).is_err());
        assert!(device_control_entry(&filled(0x27, 0xc..0x20, 1)).is_err());
    }

    #[test]
    fn the_power_counter_gather_empties_its_buffer() {
        let (mut state, mut memory) = with_device_control(&[of_type(0x32)]);
        let samples = OBJECT_928 + layout().power_counters;
        let sampled = OBJECT_928 + layout().power_counter_samples;
        memory.put(samples, &[0x5a; POWER_COUNTER_BYTES]);
        memory.put_u32(sampled, 3);
        // The selection list beside it is the kext's and stays.
        memory.put_u32(OBJECT_928 + 0xca34, 0x11);
        ring(&mut state, &mut memory).unwrap();
        let mut buffer = [0xff; POWER_COUNTER_BYTES];
        memory.read(samples, &mut buffer).unwrap();
        assert!(buffer.iter().all(|&b| b == 0));
        assert_eq!(memory.read_u32(sampled), Ok(0));
        assert_eq!(memory.read_u32(OBJECT_928 + 0xca34), Ok(0x11));
        assert_eq!(memory.read_u32(count()), Ok(1));
        assert!(device_control_entry(&filled(0x32, 4..5, 1)).is_err());
    }

    #[test]
    fn riart_settings_land_in_the_root_object() {
        let mut mask = of_type(0x34);
        mask[4..8].copy_from_slice(&0x6u32.to_le_bytes());
        let disabled = filled(0x35, 4..5, 1);
        let (mut state, mut memory) = with_device_control(&[mask, disabled]);
        ring(&mut state, &mut memory).unwrap();
        let mut riart = |offset| memory.read_u32(OBJECT_358 + offset);
        assert_eq!(riart(layout().riart_u_levels_disabled), Ok(6));
        assert_eq!(riart(layout().riart_t_disabled), Ok(1));
        assert_eq!(memory.read_u32(count()), Ok(2));
        assert!(device_control_entry(&filled(0x35, 4..5, 2)).is_err());
        assert!(device_control_entry(&filled(0x34, 8..9, 1)).is_err());
    }

    #[test]
    fn device_control_needing_a_missing_unit_refuses_by_name() {
        for (kind, reason) in [
            (0x4, "performance-counter"),
            (0x5, "performance-counter"),
            (0x9, "scheduler thread"),
            (0x1f, "context registry"),
            (0x29, "teardown thread"),
            (0x2c, "fatal"),
            (0x26, "host-allocation"),
        ] {
            let (mut state, mut memory) = with_device_control(&[of_type(kind)]);
            assert!(ring(&mut state, &mut memory).unwrap_err().contains(reason));
            assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(0));
            assert_eq!(memory.read_u32(count()), Ok(0));
        }
        // Types the kext never sends.
        for kind in [0, 1, 2, 3, 6, 0x1d, 0x20, 0x3c, 0x40] {
            assert_eq!(
                device_control_entry(&of_type(kind)),
                Err("GFX device-control type is not one the 26A434 kext sends")
            );
        }
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
        memory.put(entries + 0x14, &1u16.to_le_bytes());
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
        memory.put_u64(command + 0x14, command + 0x1000);
        memory.put_u32(command + 0x1c, 0x200);
        memory.put_u32(command + 0x1000, 7);
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
    fn each_family_reads_its_own_root_and_g13_refuses_dashboard_signals() {
        use crate::platform::apple::agx::generation::{G14X, G16X};
        // A G14X firmware refuses the G13G/G13X/G14G root.
        let mut memory = Flat::new(BASE, 0x20000);
        kext_root(&mut memory);
        let mut g14x = State::new(&G14X);
        g14x.init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        assert_eq!(
            g14x.dma(&mut memory, &mut Vec::new()),
            Err("GFX initdata root lacks its magic")
        );
        assert_eq!(
            with_device_control_on(&G16X, &[]).err(),
            Some("the GPU family's initdata root magic is not recovered")
        );
        let (mut state, mut memory) = with_device_control_on(&G13G, &[]).unwrap();
        assert!(state.root.is_some());
        let (channel_state, command) = (BASE + 0xd000, BASE + 0x10000);
        let (ring_state, _) = one_3d_entry(&mut memory, channel_state, command);
        memory.put_u32(command, 0xc);
        state.doorbell(work(1, 0)).unwrap();
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err(
                "GFX dashboard signal command: this GPU family's firmware has no dashboard-signal handler"
            )
        );
        assert_eq!(memory.read_u32(ring_state + READ), Ok(0));
        assert_eq!(memory.read_u32(channel_state + 0x1000), Ok(0));
    }

    #[test]
    fn g14x_device_control_writes_its_own_offsets() {
        use crate::platform::apple::agx::generation::G14X;
        let mut mask = of_type(0x34);
        mask[4..8].copy_from_slice(&0x6u32.to_le_bytes());
        let (mut state, mut memory) = with_device_control_on(&G14X, &[]).unwrap();
        let word = BASE + 0x1f000;
        let (deprioritize, _) = dsid_entry(&mut memory, 0x14, word);
        let slot = BASE + 0x1e000 + 3 * 8;
        memory.put_u64(slot, 0x0000_0006_0000_0006);
        memory.put_u64(slot + 8, 0x0000_0007_0000_0007);
        for (n, entry) in [of_type(0x32), mask, deprioritize].iter().enumerate() {
            memory.put(CONTROL_ENTRIES + n as u64 * 0x40, entry);
        }
        memory.put_u32(CONTROL_STATE + WRITE, 3);
        let g14x = &G14X.model().unwrap().layout;
        memory.put_u32(OBJECT_928 + g14x.power_counter_samples, 3);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u32(OBJECT_928 + 0xcfc0), Ok(0));
        assert_eq!(memory.read_u32(OBJECT_358 + 0x123c), Ok(6));
        // DSID slots are 8 bytes: DSID 3's neighbour stays.
        assert_eq!(memory.read_u64(slot), Ok(0));
        assert_eq!(memory.read_u64(slot + 8), Ok(0x0000_0007_0000_0007));
        assert_eq!(memory.read_u32(word), Ok(0x700));
        // 0x32 and 0x34 are counted at the G14X offset; G14G's stays empty.
        assert_eq!(memory.read_u32(OBJECT_928 + 0xedc8), Ok(2));
        assert_eq!(memory.read_u32(count()), Ok(0));
    }

    #[test]
    fn g15g_device_control_writes_its_own_offsets() {
        use crate::platform::apple::agx::generation::G15G;
        let mut mask = of_type(0x34);
        mask[4..8].copy_from_slice(&0x6u32.to_le_bytes());
        let mut disabled = of_type(0x35);
        disabled[4..8].copy_from_slice(&1u32.to_le_bytes());
        let mut enable = filled(0x1a, 8..9, 3);
        enable[4] = 2;
        let (mut state, mut memory) = with_device_control_on(&G15G, &[]).unwrap();
        for (n, entry) in [of_type(0x32), mask, disabled, enable].iter().enumerate() {
            memory.put(CONTROL_ENTRIES + n as u64 * 0x40, entry);
        }
        memory.put_u32(CONTROL_STATE + WRITE, 4);
        memory.put_u32(OBJECT_928 + 0xcfc0, 3);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u32(OBJECT_928 + 0xcfc0), Ok(0));
        // The RIART words are packed at +0xe35 and +0xe39.
        assert_eq!(memory.read_u32(OBJECT_358 + 0xe35), Ok(6));
        assert_eq!(memory.read_u32(OBJECT_358 + 0xe39), Ok(1));
        assert_eq!(memory.read_u32(OBJECT_358 + 0x123c), Ok(0));
        // The histogram enables sit four bytes above G14X's.
        let mut bits = [0];
        memory.read(RINGS + 0x3d8, &mut bits).unwrap();
        assert_eq!(bits, [0b100]);
        memory.read(RINGS + 0x3d4, &mut bits).unwrap();
        assert_eq!(bits, [0]);
        // 0x32, 0x34 and 0x35 are counted at G14X's offset; 0x1a is not.
        assert_eq!(memory.read_u32(OBJECT_928 + 0xedc8), Ok(3));
    }

    const OWNED_CHANNEL: u64 = BASE + 0xd000;
    const OWNED_COMMAND: u64 = BASE + 0x10000;
    const OWNED_STREAM: u64 = OWNED_COMMAND + 0x400;
    const OWNED_SHARED: u64 = OWNED_COMMAND + 0x800;
    const OWNED_DRIVER: u64 = OWNED_COMMAND + 0x900;
    const OWNED_FIRMWARE: u64 = OWNED_COMMAND + 0x908;

    fn owned_signal(family: &'static Family) -> (State, Flat, u64) {
        let (mut state, mut memory) = with_device_control_on(family, &[]).unwrap();
        event::tests::event_ring(&mut memory);
        let (master, _) = one_3d_entry(&mut memory, OWNED_CHANNEL, OWNED_COMMAND);
        memory.put_u32(OWNED_COMMAND, 9);
        memory.put_u64(OWNED_COMMAND + 0x1c, OWNED_STREAM);
        memory.put_u64(OWNED_COMMAND + 0x30, OWNED_DRIVER);
        memory.put_u64(OWNED_COMMAND + 0x38, OWNED_FIRMWARE);
        memory.put_u32(OWNED_COMMAND + 0x40, 0x100);
        memory.put_u32(OWNED_COMMAND + 0x44, 2);
        memory.put_u32(OWNED_STREAM, 0xe);
        memory.put_u64(OWNED_STREAM + 0x10, 0x55);
        memory.put_u64(OWNED_STREAM + 0x18, 1);
        memory.put_u64(OWNED_STREAM + 0x28, OWNED_SHARED);
        memory.put_u64(OWNED_STREAM + 0x30, OWNED_FIRMWARE);
        memory.put_u32(OWNED_STREAM + 0x38, 0x100);
        memory.put_u32(OWNED_STREAM + 0x4c, 0x4000_0002);
        state.doorbell(work(1, 0)).unwrap();
        (state, memory, master)
    }

    struct WorkMemory {
        flat: Flat,
        fail_write: Option<usize>,
        fail_read: Option<u64>,
        writes: Vec<(u64, Vec<u8>)>,
    }

    impl Shared for WorkMemory {
        fn read(&mut self, va: u64, out: &mut [u8]) -> Result<(), &'static str> {
            if self.fail_read == Some(va) {
                self.fail_read = None;
                return Err("injected work input read fault");
            }
            self.flat.read(va, out)
        }
        fn write(&mut self, va: u64, data: &[u8]) -> Result<(), &'static str> {
            if self.fail_write == Some(self.writes.len()) {
                self.fail_write = None;
                return Err("injected work publication write fault");
            }
            self.flat.write(va, data)?;
            self.writes.push((va, data.to_vec()));
            Ok(())
        }
        fn gpu_read(
            &mut self,
            _: usize,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("a signal command cannot execute GPU reads");
        }
        fn gpu_write(
            &mut self,
            _: usize,
            _: u64,
            _: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("a signal command cannot execute GPU writes");
        }
    }

    fn owned_control(family: &'static Family, kind: u32) -> (State, Flat, u64) {
        let (mut state, mut memory) = with_device_control_on(family, &[]).unwrap();
        let layout = &family.model().unwrap().layout;
        let count = OBJECT_928 + layout.device_control_count;
        memory.put_u32(count, 7);
        let mut entry = of_type(kind);
        match kind {
            0xe | 0x14 => {
                memory.put_u64(RINGS + DSID_TABLE, BASE + 0x1e000);
                let slot = BASE + 0x1e000 + 3 * layout.dsid_slot_bytes;
                memory.put_u32(slot + 4, 5);
                entry[4..0xc].copy_from_slice(&(BASE + 0x1f000).to_le_bytes());
                entry[0xc..0x10].copy_from_slice(&0x700u32.to_le_bytes());
                entry[0x14] = 3;
                if kind == 0xe {
                    entry[0x10..0x14].copy_from_slice(&5u32.to_le_bytes());
                }
            }
            0x1a => {
                entry[4..8].copy_from_slice(&1u32.to_le_bytes());
                entry[8] = 3;
            }
            0x27 => {
                entry[4..0xc].copy_from_slice(&(BASE + 0x1f000).to_le_bytes());
            }
            0x34 => {
                entry[4..8].copy_from_slice(&6u32.to_le_bytes());
            }
            0x35 => {
                entry[4..8].copy_from_slice(&1u32.to_le_bytes());
            }
            _ => {}
        }
        memory.put(CONTROL_ENTRIES, &entry);
        memory.put_u32(CONTROL_STATE + WRITE, 1);
        state
            .doorbell(doorbell_payload(DOORBELL_FWCTL, 0x11))
            .unwrap();
        (state, memory, count)
    }

    #[test]
    fn accepted_device_controls_retain_all_effects_count_and_retirement_on_every_family() {
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for kind in [
                7,
                DEVICE_CONTROL_POWER,
                0xe,
                0x14,
                0x1a,
                0x27,
                0x32,
                0x34,
                0x35,
            ] {
                let (mut baseline, flat, _) = owned_control(family, kind);
                let mut complete = WorkMemory {
                    flat,
                    fail_write: None,
                    fail_read: None,
                    writes: Vec::new(),
                };
                baseline.dma(&mut complete, &mut Vec::new()).unwrap();
                for failed_write in 0..complete.writes.len() {
                    let (mut state, flat, count) = owned_control(family, kind);
                    let mut memory = WorkMemory {
                        flat,
                        fail_write: Some(failed_write),
                        fail_read: None,
                        writes: Vec::new(),
                    };
                    assert_eq!(
                        state.dma(&mut memory, &mut Vec::new()),
                        Err("injected work publication write fault")
                    );
                    assert!(state.dma_pending());
                    assert_eq!(memory.writes.len(), failed_write);
                    // Every form, target, DSID comparison and derived bitmask
                    // was accepted before the first command write. A later
                    // error cannot redispatch a changed AP entry.
                    memory.flat.put_u32(CONTROL_ENTRIES, 0xffff);
                    state.dma(&mut memory, &mut Vec::new()).unwrap();
                    assert_eq!(memory.writes, complete.writes);
                    assert_eq!(state.device_control.get(&kind), Some(&1));
                    assert_eq!(state.power.len(), usize::from(kind == DEVICE_CONTROL_POWER));
                    let expected = if matches!(kind, 0xe | 0x14 | 0x1a) {
                        7
                    } else {
                        8
                    };
                    assert_eq!(memory.flat.read_u32(count), Ok(expected));
                    assert_eq!(memory.flat.read_u32(CONTROL_STATE), Ok(1));
                    assert!(!state.dma_pending());
                    state.dma(&mut memory, &mut Vec::new()).unwrap();
                    assert_eq!(memory.writes, complete.writes);
                    assert_eq!(state.device_control.get(&kind), Some(&1));
                }
            }
        }
    }

    #[test]
    fn dsid_priority_read_fault_preserves_the_source_ordered_store_and_accepted_identity() {
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            let (mut state, flat, _) = owned_control(family, 0xe);
            let slot = BASE + 0x1e000 + 3 * family.model().unwrap().layout.dsid_slot_bytes;
            let mut memory = WorkMemory {
                flat,
                fail_write: None,
                fail_read: Some(slot + 4),
                writes: Vec::new(),
            };
            assert_eq!(
                state.dma(&mut memory, &mut Vec::new()),
                Err("injected work input read fault")
            );
            assert_eq!(memory.writes, [(slot, 5u32.to_le_bytes().to_vec())]);
            assert_eq!(memory.flat.read_u32(slot), Ok(5));
            assert!(state.active_control.is_some() && state.dma_pending());
            memory.flat.put_u32(CONTROL_ENTRIES + 0xc, 0x800);
            memory.flat.put_u32(CONTROL_ENTRIES + 0x10, 99);
            memory.flat.put_u32(slot, 42); // must not replay the priority store
            state.dma(&mut memory, &mut Vec::new()).unwrap();
            assert_eq!(memory.flat.read_u64(slot), Ok(0));
            assert_eq!(memory.flat.read_u32(BASE + 0x1f000), Ok(0x700));
            assert_eq!(
                memory
                    .writes
                    .iter()
                    .filter(|(at, bytes)| *at == slot && bytes.len() == 4)
                    .count(),
                1
            );
            assert_eq!(state.device_control.get(&0xe), Some(&1));
        }
    }

    #[test]
    fn dsid_control_refuses_wrapped_table_pointers_and_complete_slot_extents_without_effects() {
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            let layout = &family.model().unwrap().layout;
            for kind in [0xe, 0x14] {
                let (state, flat, _) = owned_control(family, kind);
                let mut memory = WorkMemory {
                    flat,
                    fail_write: None,
                    fail_read: None,
                    writes: Vec::new(),
                };
                let descriptor = ring::Descriptor {
                    state: CONTROL_STATE,
                    entries: CONTROL_ENTRIES,
                };
                let mut entry = [0; 0x40];
                memory.read(CONTROL_ENTRIES, &mut entry).unwrap();
                let original = state.root.as_ref().unwrap();
                for rings in [u64::MAX - DSID_TABLE + 1, u64::MAX - DSID_TABLE - 3] {
                    let mut root = original.clone();
                    root.rings = rings;
                    assert_eq!(
                        ActiveControl::accept(&mut memory, &root, layout, descriptor, 0, &entry)
                            .unwrap_err(),
                        "GFX HWDSID table pointer wraps"
                    );
                    assert!(memory.writes.is_empty());
                }
                let offset = 3 * layout.dsid_slot_bytes;
                for table in [
                    u64::MAX - offset + 1,
                    u64::MAX - offset - layout.dsid_slot_bytes + 2,
                ] {
                    memory.flat.put_u64(RINGS + DSID_TABLE, table);
                    assert!(
                        ActiveControl::accept(&mut memory, original, layout, descriptor, 0, &entry)
                            .unwrap_err()
                            .contains("table slot")
                    );
                    assert!(memory.writes.is_empty());
                }
            }
        }
    }

    #[test]
    fn dsid_priority_captured_match_survives_faults_with_overlapping_completion_targets() {
        for matched in [4u32, 5] {
            let (mut state, flat, _) = owned_control(&G14G, 0xe);
            let slot = BASE + 0x1e000 + 3 * layout().dsid_slot_bytes;
            let mut memory = WorkMemory {
                flat,
                fail_write: Some(1),
                fail_read: None,
                writes: Vec::new(),
            };
            memory.flat.put_u32(slot + 4, matched);
            // Completion overwrites the matching word. Its value must not
            // be observed as a new match while retrying a later phase.
            memory.flat.put_u64(CONTROL_ENTRIES + 4, slot + 4);
            memory.flat.put_u32(CONTROL_ENTRIES + 0xc, 0x900);
            assert_eq!(
                state.dma(&mut memory, &mut Vec::new()),
                Err("injected work publication write fault")
            );
            memory
                .flat
                .put_u32(slot + 4, if matched == 4 { 5 } else { 4 });
            state.dma(&mut memory, &mut Vec::new()).unwrap();
            assert_eq!(
                memory.flat.read_u32(slot),
                Ok(if matched == 5 { 0 } else { 5 })
            );
            assert_eq!(memory.flat.read_u32(slot + 4), Ok(0x900));
            let expected = if matched == 5 {
                alloc::vec![slot, slot, slot + 4, CONTROL_STATE]
            } else {
                alloc::vec![slot, slot + 4, CONTROL_STATE]
            };
            assert_eq!(
                memory.writes.iter().map(|(at, _)| *at).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn a_device_control_pre_effect_input_fault_accepts_no_entry() {
        let (mut state, flat, _) = owned_control(&G14G, 0x1a);
        let enables = RINGS + layout().histogram_enables;
        let mut memory = WorkMemory {
            flat,
            fail_write: None,
            fail_read: Some(enables),
            writes: Vec::new(),
        };
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("injected work input read fault")
        );
        assert!(memory.writes.is_empty() && state.active_control.is_none());
        assert!(state.device_control.is_empty());
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        assert_eq!(state.device_control.get(&0x1a), Some(&1));
    }

    #[test]
    fn device_control_counter_read_and_write_have_separate_retained_phases() {
        let (mut state, flat, count) = owned_control(&G14G, 0x27);
        let mut memory = WorkMemory {
            flat,
            fail_write: None,
            fail_read: Some(count),
            writes: Vec::new(),
        };
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("injected work input read fault")
        );
        assert_eq!(memory.writes.len(), 1); // timeout effect precedes common-tail count read
        assert_eq!(memory.flat.read_u32(BASE + 0x1f038), Ok(1));
        memory.flat.put_u32(count, u32::MAX);
        memory.fail_write = Some(1); // fail the counter write after capturing its wraparound result
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("injected work publication write fault")
        );
        memory.flat.put_u32(count, 777);
        memory.fail_write = Some(2); // commit captured count, then fail final retirement
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("injected work publication write fault")
        );
        assert_eq!(memory.flat.read_u32(count), Ok(0));
        assert_eq!(state.device_control.get(&0x27), Some(&1));
        memory.flat.put_u32(count, 888);
        let protocol = Protocol(Rc::new(RefCell::new(state)));
        assert!(Message(protocol.clone()).check_reset().is_err());
        protocol
            .0
            .borrow_mut()
            .dma(&mut memory, &mut Vec::new())
            .unwrap();
        assert_eq!(memory.flat.read_u32(count), Ok(888)); // no repeated count after retirement fault
        assert_eq!(
            memory.writes.iter().map(|(at, _)| *at).collect::<Vec<_>>(),
            [BASE + 0x1f038, count, CONTROL_STATE]
        );
        assert_eq!(
            protocol.with(|state| state.device_control.get(&0x27).copied()),
            Some(1)
        );
        Message(protocol).check_reset().unwrap();
    }

    #[test]
    fn device_control_count_reads_after_the_original_effect_even_when_targets_overlap() {
        let (mut state, mut memory, count) = owned_control(&G14G, 0x27);
        memory.put_u64(CONTROL_ENTRIES + 4, count - LATE_EVAL_TIMED_OUT);
        state.dma(&mut memory, &mut Vec::new()).unwrap();
        assert_eq!(memory.read_u32(count), Ok(2)); // timeout writes1, common tail reads1 then writes2
    }

    #[test]
    fn accepted_signal_actions_survive_every_publication_fault_without_replay() {
        use event::tests::{EVENT_ENTRIES, EVENT_STATE, entry};
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for failed_write in 0..11 {
                let (mut state, flat, master) = owned_signal(family);
                let mut memory = WorkMemory {
                    flat,
                    fail_write: Some(failed_write),
                    fail_read: None,
                    writes: Vec::new(),
                };
                let mut outbox = Vec::new();
                assert_eq!(
                    state.dma(&mut memory, &mut outbox),
                    Err("injected work publication write fault")
                );
                assert_eq!(memory.writes.len(), failed_write);
                assert!(state.dma_pending());
                // The accepted command owns these original values. Altering
                // source memory during recovery cannot redispatch it, lose
                // its event, or change the target completion identity.
                // The entry is already accepted even if its tail publication
                // faults. The signal itself is accepted only after both words.
                memory.flat.put(BASE + 0xc014, &2u16.to_le_bytes());
                memory.flat.put_u32(OWNED_CHANNEL + 0x1040, 2);
                if failed_write >= 2 {
                    memory.flat.put_u64(OWNED_STREAM + 0x10, 0xdead);
                    memory.flat.put_u64(OWNED_STREAM + 0x18, 77);
                    memory
                        .flat
                        .put_u64(OWNED_STREAM + 0x30, OWNED_COMMAND + 0xa00);
                    memory.flat.put_u32(OWNED_COMMAND + 0x40, 0xbeef);
                    memory.flat.put_u32(OWNED_COMMAND + 0x50, 9);
                }
                if failed_write == 10 {
                    // Final master retirement has already been accepted;
                    // it must not reopen the channel before publishing it.
                    memory.fail_read = Some(OWNED_CHANNEL + 0x1000);
                }
                state.dma(&mut memory, &mut outbox).unwrap();
                assert!(!state.dma_pending());
                assert_eq!((state.commands, state.events), (1, 2));
                assert_eq!(outbox.len(), 2);
                assert_eq!(
                    memory.writes.iter().map(|(va, _)| *va).collect::<Vec<_>>(),
                    [
                        OWNED_CHANNEL + 0x28,
                        OWNED_CHANNEL + 0x1030,
                        OWNED_SHARED,
                        EVENT_ENTRIES,
                        EVENT_STATE + WRITE,
                        OWNED_FIRMWARE,
                        OWNED_DRIVER,
                        EVENT_ENTRIES + event::ENTRY_BYTES as u64,
                        EVENT_STATE + WRITE,
                        OWNED_CHANNEL + 0x1000,
                        master,
                    ]
                );
                assert_eq!(memory.flat.read_u64(OWNED_SHARED), Ok(1));
                assert_eq!(memory.flat.read_u32(OWNED_FIRMWARE), Ok(0x100));
                assert_eq!(memory.flat.read_u32(OWNED_DRIVER), Ok(0x100));
                assert_eq!(memory.flat.read_u32(OWNED_COMMAND + 0xa00), Ok(0));
                assert_eq!(
                    entry(&mut memory.flat, 0),
                    event::Event::SharedSignal {
                        id: 0x55,
                        value: 1,
                        flag: 0
                    }
                    .encode()
                );
                assert_eq!(
                    entry(&mut memory.flat, 1),
                    event::Event::Flag(1 << 2).encode()
                );
                assert_eq!(memory.flat.read_u32(EVENT_STATE + WRITE), Ok(2));
                assert_eq!(memory.flat.read_u32(OWNED_CHANNEL + 0x1000), Ok(1));
                assert_eq!(memory.flat.read_u32(master), Ok(1));
                if failed_write == 10 {
                    assert_eq!(memory.fail_read, Some(OWNED_CHANNEL + 0x1000));
                }
                // An idle later poll cannot replay the completed command.
                state.dma(&mut memory, &mut outbox).unwrap();
                assert_eq!((memory.writes.len(), outbox.len()), (11, 2));
            }
        }
    }

    #[test]
    fn submitted_tail_stops_before_later_commands_including_wrap_and_empty_intervals() {
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            for wrapping in [false, true] {
                let (mut state, mut memory, master) = owned_signal(family);
                let queue = OWNED_CHANNEL + 0x1000;
                let pointers = OWNED_CHANNEL + 0x2000;
                let entries = BASE + 0xc000;
                let (read, target, write) = if wrapping {
                    (127, 0u16, 1)
                } else {
                    (0, 1u16, 2)
                };
                memory.put_u32(queue, read);
                memory.put_u32(queue + 0x40, write);
                memory.put(entries + 0x14, &target.to_le_bytes());
                memory.put_u64(pointers + u64::from(read) * 8, OWNED_COMMAND);
                // A second AP command is already published in the channel,
                // but belongs to the next data-master entry. It must not be
                // executed or block completion of the accepted interval.
                let later = OWNED_COMMAND + 0xb00;
                memory.put_u32(later, 1); // source-qualified but unexecuted 3D
                memory.put_u64(later + 0x14, later + 0x1000);
                memory.put_u32(later + 0x1c, 0x200);
                memory.put_u32(later + 0x1000, 7);
                memory.put_u64(pointers + u64::from(target) * 8, later);
                let mut outbox = Vec::new();
                state.dma(&mut memory, &mut outbox).unwrap();
                assert_eq!((state.commands, state.events), (1, 2));
                assert_eq!(memory.read_u32(queue), Ok(u32::from(target)));
                assert_eq!(memory.read_u32(OWNED_CHANNEL + 0x28), Ok(u32::from(target)));
                assert_eq!(memory.read_u32(queue + 0x30), Ok(u32::from(target)));
                assert_eq!(memory.read_u32(master), Ok(1));

                // Repeated empty intervals cannot drain a live WRITE either.
                let second = entries + Kind::DataMaster.entry_bytes() as u64;
                memory.put_u64(second + 8, OWNED_CHANNEL);
                memory.put_u32(second + 0x10, 1);
                memory.put(second + 0x14, &target.to_le_bytes());
                memory.put_u32(master + WRITE, 2);
                state.doorbell(work(1, 0)).unwrap();
                state.dma(&mut memory, &mut outbox).unwrap();
                assert_eq!(memory.read_u32(master), Ok(2));
                assert_eq!((state.commands, outbox.len()), (1, 2));

                // Only the next entry carrying the new tail can acquire it.
                let third = second + Kind::DataMaster.entry_bytes() as u64;
                memory.put_u64(third + 8, OWNED_CHANNEL);
                memory.put_u32(third + 0x10, 1);
                memory.put(third + 0x14, &(write as u16).to_le_bytes());
                memory.put_u32(master + WRITE, 3);
                state.doorbell(work(1, 0)).unwrap();
                assert_eq!(
                    state.dma(&mut memory, &mut outbox),
                    Err("GFX 3D command (type 1) is not executed")
                );
                assert_eq!(memory.read_u32(master), Ok(2));
                assert_eq!(memory.read_u32(queue), Ok(u32::from(target)));
                assert_eq!((state.commands, outbox.len()), (1, 2));
            }
        }
    }

    #[test]
    fn wrapped_submission_keeps_its_tail_after_final_retirement_fault_and_late_append() {
        let (mut state, flat, master) = owned_signal(&G14G);
        let mut memory = WorkMemory {
            flat,
            fail_write: Some(10),
            fail_read: None,
            writes: Vec::new(),
        };
        let queue = OWNED_CHANNEL + 0x1000;
        memory.flat.put_u32(queue, 127);
        memory.flat.put_u32(queue + 0x40, 0);
        memory
            .flat
            .put_u64(OWNED_CHANNEL + 0x2000 + 127 * 8, OWNED_COMMAND);
        memory.flat.put(BASE + 0xc014, &0u16.to_le_bytes());
        let mut outbox = Vec::new();
        assert_eq!(
            state.dma(&mut memory, &mut outbox),
            Err("injected work publication write fault")
        );
        assert_eq!(memory.flat.read_u32(queue), Ok(0));
        assert_eq!(memory.flat.read_u32(master), Ok(0));
        let later = OWNED_COMMAND + 0xb00;
        memory.flat.put_u32(later, 1);
        memory.flat.put_u64(OWNED_CHANNEL + 0x2000, later);
        memory.flat.put_u32(queue + 0x40, 1);
        memory.flat.put(BASE + 0xc014, &1u16.to_le_bytes());
        memory.fail_read = Some(queue);
        state.dma(&mut memory, &mut outbox).unwrap();
        assert_eq!(memory.fail_read, Some(queue));
        assert_eq!(memory.flat.read_u32(queue), Ok(0));
        assert_eq!(memory.flat.read_u32(master), Ok(1));
        assert_eq!(
            (state.commands, outbox.len(), memory.writes.len()),
            (1, 2, 11)
        );
    }

    #[test]
    fn submitted_tail_refuses_unpublished_or_out_of_range_pointers_before_effects() {
        for target in [2u16, 128] {
            let (mut state, flat, master) = owned_signal(&G14G);
            let mut memory = WorkMemory {
                flat,
                fail_write: None,
                fail_read: None,
                writes: Vec::new(),
            };
            memory.flat.put(BASE + 0xc014, &target.to_le_bytes());
            assert!(
                state
                    .dma(&mut memory, &mut Vec::new())
                    .unwrap_err()
                    .contains("submitted command tail")
            );
            assert!(memory.writes.is_empty());
            assert_eq!(memory.flat.read_u32(master), Ok(0));
            assert_eq!((state.commands, state.events), (0, 0));
        }
    }

    #[test]
    fn signal_scalar_crossing_a_uat_page_refuses_before_signal_effects() {
        let (mut state, flat, _) = owned_signal(&G14G);
        let mut memory = WorkMemory {
            flat,
            fail_write: None,
            fail_read: None,
            writes: Vec::new(),
        };
        memory.flat.put_u64(OWNED_STREAM + 0x28, BASE + 0x1bffc);
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX scalar publication crosses a UAT page")
        );
        assert_eq!(memory.writes.len(), 2); // accepted master tail only
        assert_eq!((state.commands, state.events), (0, 0));
    }

    #[test]
    fn full_event_ring_retains_work_between_shared_signal_and_completion() {
        use event::tests::{EVENT_STATE, entry};
        let (mut state, flat, master) = owned_signal(&G14G);
        let mut memory = WorkMemory {
            flat,
            fail_write: None,
            fail_read: None,
            writes: Vec::new(),
        };
        memory.flat.put_u32(EVENT_STATE + WRITE, 0xff);
        let mut outbox = Vec::new();
        state.dma(&mut memory, &mut outbox).unwrap();
        assert_eq!(memory.writes.len(), 3);
        assert_eq!(memory.flat.read_u64(OWNED_SHARED), Ok(1));
        assert_eq!(memory.flat.read_u32(OWNED_FIRMWARE), Ok(0));
        assert_eq!(memory.flat.read_u32(OWNED_DRIVER), Ok(0));
        assert!(outbox.is_empty() && state.dma_pending());
        // The existing reset contract observes the still-owned work.
        let protocol = Protocol(Rc::new(RefCell::new(state)));
        assert!(Message(protocol.clone()).check_reset().is_err());
        memory.flat.put_u32(EVENT_STATE + READ, 1);
        protocol
            .0
            .borrow_mut()
            .dma(&mut memory, &mut outbox)
            .unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(memory.flat.read_u32(OWNED_FIRMWARE), Ok(0x100));
        assert_eq!(memory.flat.read_u32(OWNED_DRIVER), Ok(0x100));
        assert_eq!(memory.flat.read_u32(OWNED_CHANNEL + 0x1000), Ok(0));
        assert_eq!(
            entry(&mut memory.flat, 0xff),
            event::Event::SharedSignal {
                id: 0x55,
                value: 1,
                flag: 0
            }
            .encode()
        );
        assert!(Message(protocol.clone()).check_reset().is_err());
        memory.flat.put_u32(EVENT_STATE + READ, 2);
        protocol
            .0
            .borrow_mut()
            .dma(&mut memory, &mut outbox)
            .unwrap();
        assert_eq!(
            entry(&mut memory.flat, 0),
            event::Event::Flag(1 << 2).encode()
        );
        assert_eq!(outbox.len(), 2);
        assert_eq!(memory.flat.read_u32(master), Ok(1));
        assert_eq!(
            memory
                .writes
                .iter()
                .filter(|(va, _)| *va == OWNED_SHARED)
                .count(),
            1
        );
        assert!(!protocol.with(State::dma_pending));
        Message(protocol).check_reset().unwrap();
    }

    #[test]
    fn failed_signal_acceptance_keeps_only_the_accepted_master_tail() {
        let (mut state, flat, _) = owned_signal(&G14G);
        let mut memory = WorkMemory {
            flat,
            fail_write: None,
            fail_read: Some(OWNED_COMMAND + 0x50),
            writes: Vec::new(),
        };
        let mut outbox = Vec::new();
        assert_eq!(
            state.dma(&mut memory, &mut outbox),
            Err("injected work input read fault")
        );
        assert_eq!(memory.writes.len(), 2);
        assert!(outbox.is_empty());
        assert_eq!(memory.flat.read_u64(OWNED_SHARED), Ok(0));
        memory.flat.put_u64(OWNED_STREAM + 0x20, 1 << 3);
        assert!(
            state
                .dma(&mut memory, &mut outbox)
                .unwrap_err()
                .contains("mask bit 3")
        );
        assert_eq!(memory.writes.len(), 2);
        assert!(outbox.is_empty());
        memory.flat.put_u64(OWNED_STREAM + 0x20, 0);
        state.dma(&mut memory, &mut outbox).unwrap();
        assert_eq!((state.commands, state.events), (1, 2));
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
    fn the_root_must_be_the_kexts_before_any_doorbell_runs() {
        let mut memory = Flat::new(BASE, 0x20000);
        let mut state = State::new(&G14G);
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX initdata root lacks its magic")
        );
        assert!(state.dma_pending());
        let mut early = State::new(&G14G);
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
        let mut ram = Ram::new(base, 0x4000 * 6);
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
        // The status object root+a8 names is a distinct mapped page.
        let (_, status_idx) = uat::indices(va + 0x4000);
        ram.put_u64(
            base + 0xc000 + status_idx[2] as u64 * 8,
            uat::encode_pte(base + 0x1_4000, &flags),
        );
        let mut table = Uat::new(40);
        table.configure(base).unwrap();
        let mut latch = InterruptLatch::new();
        let mut state = State::new(&G14G);
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
        ram.put_u64(at, MAGIC_G13_G14G);
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
