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
use super::generation::Family;
use super::initdata::{self, Root};
use super::observe::{self, Journal};
use super::ring::{self, Kind, Shared};
use super::signal;
use super::uat;
use crate::platform::dma::Port;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
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
/// The device-control power-transition notice (`AGXAccelerator::
/// powerStateDidChangeTo`/`WillChangeTo` 0x1af8508/0x1af861c).
const DEVICE_CONTROL_POWER: u32 = 0x28;
/// The device-control types the firmware counts once handled, one bit per
/// type (its byte table at 0xffffff80000593a0, read at 0xffffff8000003a2c).
const COUNTED_DEVICE_CONTROL: u64 = 0x1fff_3bfb_f3c7_bffe;
/// The handled-entry count's offset in the root's +0xb0 object, a word the
/// firmware increments after each counted entry (0xffffff8000004b8c).
const DEVICE_CONTROL_COUNT: u64 = 0xe838;
/// The ring directory's firmware VA of the HWDSID table, 0x10 bytes per
/// DSID: +0 the requested priority, +4 the firmware's matching word
/// (handlers 0xffffff80000043a0 and 0xffffff8000003ba4).
const DSID_TABLE: u64 = 0x2c8;
/// The ring directory's context-switch histogram enables, one bit per data
/// master, and the histograms themselves, 12 words per data master from
/// +0x3e5 (handler 0xffffff8000003e88; `getDMContextSwitchTimeHistogram`
/// 0x1b4eb38 reads them).
const HISTOGRAM_ENABLES: u64 = 0x3e4;
/// The data masters the kext keeps a histogram for: TA, 3D and CL, whose
/// 0x30-byte histograms fill +0x3e5..+0x475.
const HISTOGRAM_MASTERS: u32 = 3;
/// The power-counter sample buffer and its sample count in the root's +0xb0
/// object (handler 0xffffff8000003b20; `getAndGatherPowerCounterData`
/// 0x1b54b60 reads them).
const POWER_COUNTERS: u64 = 0xca48;
const POWER_COUNTER_BYTES: usize = 0x1800;
const POWER_COUNTER_SAMPLES: u64 = 0xca30;
/// The RIART U-level disable mask and T-disable word in the root's +0x20
/// object (handlers 0xffffff8000004678 and 0xffffff8000003d24).
const RIART_U_LEVELS_DISABLED: u64 = 0xe30;
const RIART_T_DISABLED: u64 = 0xe34;
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
        offset: u64,
        value: u32,
    },
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
#[derive(Debug)]
pub struct State {
    /// The AGX family whose kext and firmware fix the interface.
    family: &'static Family,
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
    /// Device-control entries consumed, by type.
    pub device_control: BTreeMap<u32, u64>,
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
    /// A fresh protocol state for `family`'s interface, observing work
    /// commands when `observe`.
    fn new(family: &'static Family, observe: bool) -> Self {
        State {
            family,
            initdata_va: None,
            initdata_checked: false,
            root: None,
            work: Vec::new(),
            fwctl: 0,
            power: Vec::new(),
            device_control: BTreeMap::new(),
            commands: 0,
            events: 0,
            jobs: VecDeque::new(),
            observe: observe.then(Journal::default),
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
            let magic = self
                .family
                .initdata_magic
                .ok_or("the GPU family's initdata root magic is not recovered")?;
            let root = Root::read(memory, uat::canonical_firmware_va(va), magic)?;
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
            let kind = u32::from_le_bytes(entry[..4].try_into().unwrap());
            let counted = COUNTED_DEVICE_CONTROL
                .checked_shr(kind)
                .is_some_and(|bits| bits & 1 != 0);
            match device_control_entry(&entry)? {
                Command::Power(notice) => self.power.push(notice),
                Command::Private => {}
                Command::DsidPriority {
                    dsid,
                    priority,
                    pointer,
                    value,
                } => {
                    let slot = dsid_slot(memory, root, dsid)?;
                    memory.write(slot, &priority.to_le_bytes())?;
                    let matched = memory.read_u32(slot + 4)?;
                    if matched == priority && priority != 0 {
                        memory.write(slot, &[0; 8])?;
                    }
                    memory.write(pointer, &value.to_le_bytes())?;
                }
                Command::DsidDeprioritize {
                    dsid,
                    pointer,
                    value,
                } => {
                    let slot = dsid_slot(memory, root, dsid)?;
                    memory.write(slot, &[0; 8])?;
                    memory.write(pointer, &value.to_le_bytes())?;
                }
                Command::Histogram { master, enable } => {
                    let at = root.rings + HISTOGRAM_ENABLES;
                    let mut enables = [0];
                    memory.read(at, &mut enables)?;
                    let bit = 1 << master;
                    enables[0] = if enable {
                        enables[0] | bit
                    } else {
                        enables[0] & !bit
                    };
                    memory.write(at, &enables)?;
                }
                Command::LateEvalTimeout { wait } => {
                    memory.write(wait + LATE_EVAL_TIMED_OUT, &1u32.to_le_bytes())?;
                }
                Command::PowerCounters => {
                    let samples = root.object_928 + POWER_COUNTERS;
                    memory.write(samples, &[0; POWER_COUNTER_BYTES])?;
                    memory.write(root.object_928 + POWER_COUNTER_SAMPLES, &[0; 4])?;
                }
                Command::Riart { offset, value } => {
                    memory.write(root.object_358 + offset, &value.to_le_bytes())?;
                }
            }
            *self.device_control.entry(kind).or_default() += 1;
            if counted {
                let count = root.object_928 + DEVICE_CONTROL_COUNT;
                let handled = memory.read_u32(count)?.wrapping_add(1);
                memory.write(count, &handled.to_le_bytes())?;
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
                // Observation never changes the outcome: a record that cannot
                // be read is logged as such.
                if let Some(journal) = self.observe.as_mut() {
                    match observe::Observation::record(memory, pipe as u8, index, state, va) {
                        Ok(observation) => journal.record(&observation),
                        Err(reason) => journal.note(format!(
                            "AGX OBSERVE pipe={} index={index} command={va:#x} unrecorded: {reason}",
                            pipe as u8
                        )),
                    }
                }
                if command.kind == channel::Kind::DashboardSignal && !self.family.dashboard_signals
                {
                    return Err(
                        "GFX dashboard signal command: this GPU family's firmware has no dashboard-signal handler",
                    );
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

/// The HWDSID table slot of `dsid`, through the ring directory's table VA.
fn dsid_slot(memory: &mut dyn Shared, root: &Root, dsid: u8) -> Result<u64, &'static str> {
    let table = memory.read_u64(root.rings + DSID_TABLE)?;
    if table == 0 {
        return Err("GFX ring directory names no HWDSID table");
    }
    Ok(table + u64::from(dsid) * 0x10)
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
                offset: RIART_U_LEVELS_DISABLED,
                value: word(4),
            })
        }
        0x35 => {
            boolean("GFX RIART T-disable has fields beyond its flag")?;
            Ok(Command::Riart {
                offset: RIART_T_DISABLED,
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
    /// The protocol of `family`'s firmware, recording work commands when
    /// `observe` (`--agx-observe`).
    pub fn with_observe(family: &'static Family, observe: bool) -> Self {
        Protocol(Rc::new(RefCell::new(State::new(family, observe))))
    }

    pub fn with<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(&self.0.borrow())
    }

    /// Drain the observed work commands recorded this run, as log lines.
    pub fn observations(&self) -> Vec<String> {
        self.0.borrow_mut().observations()
    }
}

/// The GFX coprocessor: RTKit with the GFX endpoints and the firmware's DMA.
pub struct Coprocessor {
    rtkit: RtKit,
    protocol: Protocol,
}

impl Coprocessor {
    /// `family`'s GFX coprocessor, whose RTKit manages its power ordinarily
    /// (`power-managed`), recording each work command (`--agx-observe`)
    /// when `observe`, still refusing it by name.
    pub fn with_observe(family: &'static Family, observe: bool) -> Result<Self, &'static str> {
        let (endpoints, protocol) = endpoints(family, observe);
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
pub fn endpoints(family: &'static Family, observe: bool) -> (Vec<NumberedEndpoint>, Protocol) {
    let protocol = Protocol::with_observe(family, observe);
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
    use crate::platform::apple::agx::generation::{G13G, G14G, MAGIC_G13_G14G};
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
        memory.put_descriptor(RINGS + 0x1a0, CONTROL_STATE, CONTROL_ENTRIES);
        for (n, entry) in entries.iter().enumerate() {
            memory.put(CONTROL_ENTRIES + n as u64 * 0x40, entry);
        }
        memory.put_u32(CONTROL_STATE + WRITE, entries.len() as u32);
        let mut state = State::new(family, false);
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

    #[test]
    fn the_message_endpoint_captures_the_initdata_pointer_once() {
        let mut state = State::new(&G14G, false);
        let va = 0x4_1234_5000;
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_ok());
        assert_eq!(state.initdata_va, Some(va));
        // A second initdata, or any other message type, is refused.
        assert!(state.init((MSG_INIT << TYPE_SHIFT) | va).is_err());
        let mut fresh = State::new(&G14G, false);
        assert!(fresh.init(0x42 << TYPE_SHIFT).is_err());
        // A VA above 44 bits is truncated to the field the kext sends.
        let mut wide = State::new(&G14G, false);
        wide.init((MSG_INIT << TYPE_SHIFT) | INIT_VA_BITS | (1 << 44))
            .unwrap();
        assert_eq!(wide.initdata_va, Some(INIT_VA_BITS));
    }

    #[test]
    fn doorbells_take_the_kexts_forms_and_queue_firmware_work() {
        let (endpoints, protocol) = endpoints(&G14G, false);
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
        let mut state = State::new(&G14G, false);
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

    const OBJECT_928: u64 = BASE + 0x5000;
    const OBJECT_358: u64 = BASE + 0x3000;
    const COUNT: u64 = OBJECT_928 + DEVICE_CONTROL_COUNT;

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
        assert_eq!(memory.read_u32(COUNT), Ok(1));
        assert_eq!(memory.read_u32(CONTROL_STATE + READ), Ok(1));
        assert!(device_control_entry(&filled(7, 8..9, 1)).is_err());
    }

    #[test]
    fn the_configuration_snapshot_is_taken_and_left_uncounted() {
        let snapshot = of_type(0x15);
        let (mut state, mut memory) = with_device_control(&[power(0), snapshot, power(1)]);
        memory.put_u32(COUNT, 7);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(state.device_control.get(&0x15), Some(&1));
        // The two power notices are counted; the snapshot is not.
        assert_eq!(memory.read_u32(COUNT), Ok(9));
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
        assert_eq!(memory.read_u32(COUNT), Ok(entries - 4));
        assert_eq!(
            state.device_control.values().sum::<u64>(),
            u64::from(entries)
        );
        // Nothing else the AP shares changed.
        let mut after = memory.bytes.clone();
        for at in [CONTROL_STATE + READ, COUNT] {
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
        (entry, table + 3 * 0x10)
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
        assert_eq!(memory.read_u32(COUNT), Ok(0));
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
        assert_eq!(memory.read_u32(COUNT), Ok(0));
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
        let enables = RINGS + HISTOGRAM_ENABLES;
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
        assert_eq!(memory.read_u32(COUNT), Ok(0));
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
        assert_eq!(memory.read_u32(COUNT), Ok(1));
        entry[0x20] = 1;
        assert!(device_control_entry(&entry).is_err());
        assert!(device_control_entry(&filled(0x27, 0xc..0x20, 1)).is_err());
    }

    #[test]
    fn the_power_counter_gather_empties_its_buffer() {
        let (mut state, mut memory) = with_device_control(&[of_type(0x32)]);
        let samples = OBJECT_928 + POWER_COUNTERS;
        memory.put(samples, &[0x5a; POWER_COUNTER_BYTES]);
        memory.put_u32(OBJECT_928 + POWER_COUNTER_SAMPLES, 3);
        // The selection list beside it is the kext's and stays.
        memory.put_u32(OBJECT_928 + 0xca34, 0x11);
        ring(&mut state, &mut memory).unwrap();
        let mut buffer = [0xff; POWER_COUNTER_BYTES];
        memory.read(samples, &mut buffer).unwrap();
        assert!(buffer.iter().all(|&b| b == 0));
        assert_eq!(memory.read_u32(OBJECT_928 + POWER_COUNTER_SAMPLES), Ok(0));
        assert_eq!(memory.read_u32(OBJECT_928 + 0xca34), Ok(0x11));
        assert_eq!(memory.read_u32(COUNT), Ok(1));
        assert!(device_control_entry(&filled(0x32, 4..5, 1)).is_err());
    }

    #[test]
    fn riart_settings_land_in_the_root_object() {
        let mut mask = of_type(0x34);
        mask[4..8].copy_from_slice(&0x6u32.to_le_bytes());
        let disabled = filled(0x35, 4..5, 1);
        let (mut state, mut memory) = with_device_control(&[mask, disabled]);
        ring(&mut state, &mut memory).unwrap();
        assert_eq!(memory.read_u32(OBJECT_358 + RIART_U_LEVELS_DISABLED), Ok(6));
        assert_eq!(memory.read_u32(OBJECT_358 + RIART_T_DISABLED), Ok(1));
        assert_eq!(memory.read_u32(COUNT), Ok(2));
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
            assert_eq!(memory.read_u32(COUNT), Ok(0));
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
    fn each_family_reads_its_own_root_and_g13_refuses_dashboard_signals() {
        use crate::platform::apple::agx::generation::{G14X, G16X};
        // The kext root carries the G13G/G13X/G14G magic.
        assert_eq!(
            with_device_control_on(&G14X, &[]).err(),
            Some("GFX initdata root lacks its magic")
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
        let mut state = State::new(&G14G, true);
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
        let mut quiet = State::new(&G14G, false);
        assert!(quiet.observations().is_empty());
    }

    #[test]
    fn the_root_must_be_the_kexts_before_any_doorbell_runs() {
        let mut memory = Flat::new(BASE, 0x20000);
        let mut state = State::new(&G14G, false);
        state
            .init((MSG_INIT << TYPE_SHIFT) | (ROOT & INIT_VA_BITS))
            .unwrap();
        assert_eq!(
            state.dma(&mut memory, &mut Vec::new()),
            Err("GFX initdata root lacks its magic")
        );
        assert!(state.dma_pending());
        let mut early = State::new(&G14G, false);
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
        let mut state = State::new(&G14G, false);
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
