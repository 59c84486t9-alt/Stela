//! Retained Stela-native CIO execution over the canonical T6000 SRAM.
//!
//! LLB471b8 binds the four CIO groups to the shared slot at28e099068.
//! Original RCfg36/40/44/48 publish their corresponding high-bit action to
//!28e09a034. The kernel's matching request/wait pair is2f0a720/2b4b084.
//! This engine executes supplied, finalized programs; it is not a capture of
//! Apple's hidden micro-PC, cold state, or unimplemented control instructions.
use super::{Controller, Entry, Error as NativeError, effects::Effects};
use crate::platform::apple::{
    bus::Width,
    pmgr::sequencer::{self, AddressFormat, PacketCursor, PacketKind, RouteOutcome, WriteClaim},
    power::t6000::{Bank, CIO, RequestKind},
};
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::{
    cell::RefCell,
    ops::{Deref, DerefMut},
};

const BINDING: u64 = 0x28e099068;
const CIO_ADDRESS: u64 = 0x28e09a034;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Bound,
    ProgramInventory,
    FinalizedImage,
    Activation,
    Pending,
    UnsupportedRequest,
    NoRequest,
    StaleExecution,
    MissingAction,
    Action,
}
impl Error {
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Bound => "T6000 CIO native engine already has a program owner",
            Self::ProgramInventory => {
                "T6000 CIO finalized program inventory does not match actual admitted ports"
            }
            Self::FinalizedImage => {
                "T6000 CIO counted program lacks its exact final zero or known SRAM extent"
            }
            Self::Activation => {
                "T6000 CIO native execution lacks qualified source activation inputs"
            }
            Self::Pending => "T6000 CIO native engine cannot replace or duplicate pending work",
            Self::UnsupportedRequest => {
                "T6000 native request family has no qualified execution protocol"
            }
            Self::NoRequest => "T6000 CIO native engine has no accepted request",
            Self::StaleExecution => "T6000 CIO native execution handle is stale",
            Self::MissingAction => {
                "T6000 CIO final end lacks its actual matching completion action"
            }
            Self::Action => "T6000 CIO completion action does not belong to the active program",
        }
    }
}

/// Actual compiler finalization metadata, supplied before accepting requests.
/// Bytes are read from the same physically installed SRAM, never this input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    /// First-entry authority only. Later jobs inherit their actual retained
    /// Stela port context; a capture/declaration is never replayed as a reset.
    /// None retains unknown context until a real tag1c executes.
    pub initial_control: Option<sequencer::control::Initial>,
    pub port: u8,
    pub counted_words: u32,
    pub format: AddressFormat,
}
struct Image {
    program: Program,
    entry: Entry,
    entered: bool,
    context: Option<sequencer::control::Snapshot>,
}
struct Job {
    serial: u64,
    port: u8,
    entry: Entry,
    counted_words: u32,
    cursor: Rc<RefCell<PacketCursor>>,
    completion_action: bool,
}
pub(super) struct State {
    images: BTreeMap<u8, Image>,
    job: Option<Job>,
    completed: Vec<Completion>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub serial: u64,
    pub port: u8,
    pub entry: Entry,
    pub retired_at: u64,
    pub committed_writes: u64,
    pub committed_reads: u64,
}
/// Read-only inspection, never a restorable execution/completion receipt.
pub struct Observations {
    pub programs: Vec<Program>,
    pub active: Option<Active>,
    pub retained_contexts: Vec<(u8, Option<sequencer::control::Snapshot>)>,
    pub completed: Vec<Completion>,
}
pub struct Active {
    pub serial: u64,
    pub port: u8,
    pub entry: Entry,
    pub packet_pc: Option<u64>,
    pub committed_writes: u64,
    pub committed_reads: u64,
    pub completion_action: bool,
    /// None: no claim; Some(false): claimed; Some(true): dispatched.
    pub in_flight: Option<bool>,
    pub uncertain_write: Option<sequencer::PhysicalWrite>,
    pub uncertain_read: Option<sequencer::poll::PhysicalRead>,
    pub pending_poll: Option<sequencer::poll::Poll>,
    pub pending_delay: Option<u32>,
    pub control_context: Option<sequencer::control::Snapshot>,
    pub pending_copy: Option<sequencer::copy::Snapshot>,
    pub last_copy: Option<sequencer::copy::Completed>,
    pub uncertain_copy_read: Option<sequencer::copy::PhysicalRead>,
    pub uncertain_copy_write: Option<sequencer::copy::Transfer>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Packet(PacketKind),
    Delay { remaining: u32 },
    Retired(Completion),
}

/// A handle to the controller-owned job; dropping it retains the cursor and
/// all in-flight claims. A later handle resumes that same job, never replays it.
pub struct Engine {
    effects: Effects,
    serial: u64,
}
impl Deref for Engine {
    type Target = Effects;
    fn deref(&self) -> &Effects {
        &self.effects
    }
}
impl DerefMut for Engine {
    fn deref_mut(&mut self) -> &mut Effects {
        &mut self.effects
    }
}

impl Controller {
    /// Bind one complete admitted CIO program family after actual publication.
    /// This explicitly chooses a Stela-owned native execution policy. It does
    /// not grant captured Apple state, GPCE action semantics, or PS ownership.
    pub fn bind_cio_engine(&self, programs: Vec<Program>) -> Result<(), NativeError> {
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(|_| NativeError::Paused)?;
        let ports = state.geometry[0].cio_ports;
        if super::View::pending(&state) || !state.requests.is_empty() {
            return Err(NativeError::Engine(Error::Pending));
        }
        let native = state.native.as_mut().ok_or(NativeError::Unmounted)?;
        if native.engine.is_some() || native.packet_effects_owned {
            return Err(NativeError::Engine(Error::Bound));
        }
        let slot = (native.read_control(BINDING, Width::Word)? & 31) as u8;
        let mut images = BTreeMap::new();
        for program in programs {
            if program.port >= 4
                || ports & (1 << program.port) == 0
                || images.contains_key(&program.port)
            {
                return Err(NativeError::Engine(Error::ProgramInventory));
            }
            let entry = native.entry(4 + program.port, slot)?;
            let length = usize::try_from(program.counted_words)
                .ok()
                .and_then(|words| words.checked_add(1))
                .and_then(|words| words.checked_mul(4))
                .ok_or(NativeError::Geometry)?;
            super::State::byte_extent(entry.pc - super::SRAM_BASE, length)?;
            let mut bytes = vec![0; length];
            native.read_bytes(entry.pc - super::SRAM_BASE, &mut bytes)?;
            if bytes.last_chunk::<4>() != Some(&[0; 4]) {
                return Err(NativeError::Engine(Error::FinalizedImage));
            }
            images.insert(
                program.port,
                Image {
                    program,
                    entry,
                    entered: false,
                    context: None,
                },
            );
        }
        if ports == 0 || images.len() != ports.count_ones() as usize {
            return Err(NativeError::Engine(Error::ProgramInventory));
        }
        native.engine = Some(State {
            images,
            job: None,
            completed: Vec::new(),
        });
        Ok(())
    }

    pub fn cio_completions(&self) -> Result<Vec<Completion>, NativeError> {
        Ok(self
            .0
            .borrow()
            .native
            .as_ref()
            .ok_or(NativeError::Unmounted)?
            .engine
            .as_ref()
            .ok_or(NativeError::Engine(Error::ProgramInventory))?
            .completed
            .clone())
    }

    /// Start/resume the oldest actual accepted request. The job owns its PC,
    /// immutable decode image and pending effects in this same Controller.
    pub fn cio_engine(&self) -> Result<Engine, NativeError> {
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(|_| NativeError::Paused)?;
        let paused = state.paused();
        let native = state.native.as_ref().ok_or(NativeError::Unmounted)?;
        let engine = native
            .engine
            .as_ref()
            .ok_or(NativeError::Engine(Error::ProgramInventory))?;
        if let Some(job) = &engine.job {
            return Ok(Engine {
                serial: job.serial,
                effects: Effects {
                    controller: self.clone(),
                    cursor: job.cursor.clone(),
                },
            });
        }
        if !state.captured_pending.is_empty() {
            return Err(NativeError::Engine(Error::Pending));
        }
        let request = *state
            .requests
            .iter()
            .find(|request| {
                !engine
                    .completed
                    .iter()
                    .any(|done| done.serial == request.serial)
                    && !matches!(
                        request.kind,
                        RequestKind::AutomaticGating { enabled: false, .. }
                    )
            })
            .ok_or(NativeError::Engine(Error::NoRequest))?;
        let RequestKind::Cio { port } = request.kind else {
            return Err(NativeError::Engine(Error::UnsupportedRequest));
        };
        // Original activation performs both real GPCE enable stores. Unknown
        // inputs never become ready merely because a pointer is installed.
        for address in [0x28e09906c, 0x28e099074] {
            if native.read_control(address, Width::Word)? & 1 == 0 {
                return Err(NativeError::Engine(Error::Activation));
            }
        }
        let image = engine
            .images
            .get(&port)
            .ok_or(NativeError::Engine(Error::ProgramInventory))?;
        let length = (image.program.counted_words as usize + 1) * 4;
        let mut bytes = vec![0; length];
        // Decode only this accepted program from the same frozen physical SRAM;
        // metadata is not another executable store or replacement image.
        native.read_bytes(image.entry.pc - super::SRAM_BASE, &mut bytes)?;
        let mut cursor = PacketCursor::unknown();
        cursor
            .install_sram(image.entry.pc, &bytes, image.program.format)
            .map_err(NativeError::Cursor)?;
        if image.entered {
            if let Some(context) = image.context {
                cursor
                    .inherit_control(context)
                    .map_err(NativeError::Cursor)?;
            }
        } else if let Some(initial) = image.program.initial_control {
            cursor
                .bind_initial_control(initial)
                .map_err(NativeError::Cursor)?;
        }
        cursor.set_suspended(paused);
        let job = Job {
            serial: request.serial,
            port,
            entry: image.entry,
            counted_words: image.program.counted_words,
            cursor: Rc::new(RefCell::new(cursor)),
            completion_action: false,
        };
        let handle = Engine {
            serial: job.serial,
            effects: Effects {
                controller: self.clone(),
                cursor: job.cursor.clone(),
            },
        };
        let engine = state
            .native
            .as_mut()
            .expect("checked native owner")
            .engine
            .as_mut()
            .expect("checked program family");
        let image = engine.images.get_mut(&port).expect("checked port");
        image.entered = true;
        image.context = job.cursor.borrow().control_context();
        engine.job = Some(job);
        Ok(handle)
    }
}

impl State {
    pub(super) fn observe(&self) -> Observations {
        Observations {
            programs: self.images.values().map(|image| image.program).collect(),
            completed: self.completed.clone(),
            retained_contexts: self
                .images
                .iter()
                .map(|(&port, image)| (port, image.context))
                .collect(),
            active: self.job.as_ref().map(|job| {
                let cursor = job.cursor.borrow();
                Active {
                    serial: job.serial,
                    port: job.port,
                    entry: job.entry,
                    packet_pc: cursor.packet_pc(),
                    committed_writes: cursor.committed_writes(),
                    committed_reads: cursor.committed_reads(),
                    completion_action: job.completion_action,
                    in_flight: cursor.in_flight(),
                    uncertain_write: cursor.uncertain_write(),
                    uncertain_read: cursor.uncertain_read(),
                    pending_poll: cursor.pending_poll(),
                    pending_delay: cursor.pending_delay(),
                    control_context: cursor.control_context(),
                    pending_copy: cursor.pending_copy(),
                    last_copy: cursor.last_copy(),
                    uncertain_copy_read: cursor.uncertain_copy_read(),
                    uncertain_copy_write: cursor.uncertain_copy_write(),
                }
            }),
        }
    }
    pub(super) fn accepting(&self, requests: &[super::super::Request]) -> bool {
        !requests.iter().any(|request| {
            matches!(request.kind, RequestKind::Cio { .. })
                && !self
                    .completed
                    .iter()
                    .any(|done| done.serial == request.serial)
        })
    }
    pub(super) fn completed(&self, serial: u64) -> bool {
        self.completed.iter().any(|done| done.serial == serial)
    }
}
impl Engine {
    /// Commit the source's high-bit CIO action through its actual controller
    /// owner. Only a dispatched claim of this job can submit it. Ordinary AP
    /// writes have no such authority. Other physical targets return false and
    /// must use the mount's existing checked RAM/MMIO route with typed outcomes.
    pub fn commit_controller_write(&mut self, claim: &WriteClaim) -> Result<bool, NativeError> {
        let write = claim.write();
        if write.address != CIO_ADDRESS {
            return Ok(false);
        }
        self.effects.refresh_pause().map_err(NativeError::Cursor)?;
        let mut state = self.effects.controller.0.borrow_mut();
        if state.paused() {
            return Err(NativeError::Paused);
        }
        let engine = state
            .native
            .as_mut()
            .ok_or(NativeError::Unmounted)?
            .engine
            .as_mut()
            .ok_or(NativeError::Engine(Error::StaleExecution))?;
        let job = engine
            .job
            .as_mut()
            .filter(|job| job.serial == self.serial)
            .ok_or(NativeError::Engine(Error::StaleExecution))?;
        if write.width != Width::Word
            || write.value != (1u64 << (16 + job.port))
            || job.completion_action
        {
            return Err(NativeError::Engine(Error::Action));
        }
        // finish_write checks private cursor/ticket/dispatched ownership before
        // any controller mutation. This physical action only latches retirement
        // intent; it cannot acknowledge a still-running native program.
        self.effects
            .cursor
            .borrow_mut()
            .finish_write::<()>(claim, RouteOutcome::Committed)
            .map_err(|error| match error {
                sequencer::FinishError::Ownership(error, _) => NativeError::Cursor(error),
                _ => unreachable!("committed outcome cannot be a routed error"),
            })?;
        job.completion_action = true;
        Ok(true)
    }

    /// Execute internal delay/end progress. Physical reads/writes remain
    /// exclusive claimed effects. No external completion receipt is accepted.
    pub fn advance(&mut self, now: u64) -> Result<Progress, NativeError> {
        {
            let mut state = self.effects.controller.0.borrow_mut();
            let running = state.clock_running();
            let native = state.native.as_mut().ok_or(NativeError::Unmounted)?;
            if !native
                .engine
                .as_ref()
                .and_then(|engine| engine.job.as_ref())
                .is_some_and(|job| job.serial == self.serial)
            {
                return Err(NativeError::Engine(Error::StaleExecution));
            }
            if let Some(clock) = native.clock.as_mut() {
                clock.observe(now, running).map_err(NativeError::Clock)?;
            }
        }
        self.effects.refresh_pause().map_err(NativeError::Cursor)?;
        self.effects
            .cursor
            .borrow()
            .check_progress()
            .map_err(NativeError::Cursor)?;
        let kind = self.effects.packet_kind();
        match kind {
            Ok(PacketKind::Control) => {
                self.effects
                    .advance_control()
                    .map_err(NativeError::Cursor)?;
                match self.effects.packet_kind() {
                    Ok(packet) => Ok(Progress::Packet(packet)),
                    Err(sequencer::Error::UnqualifiedRetirement) => self.retire(now),
                    Err(error) => Err(NativeError::Cursor(error)),
                }
            }
            Ok(PacketKind::CopyJoin) => {
                self.effects
                    .advance_copy_join()
                    .map_err(NativeError::Cursor)?;
                match self.effects.packet_kind() {
                    Ok(packet) => Ok(Progress::Packet(packet)),
                    Err(sequencer::Error::UnqualifiedRetirement) => self.retire(now),
                    Err(error) => Err(NativeError::Cursor(error)),
                }
            }
            Ok(PacketKind::Delay) => {
                let progress = self.effects.advance_delay(now)?;
                if !progress.complete {
                    return Ok(Progress::Delay {
                        remaining: progress.remaining,
                    });
                }
                match self.effects.packet_kind() {
                    Ok(packet) => Ok(Progress::Packet(packet)),
                    Err(sequencer::Error::UnqualifiedRetirement) => self.retire(now),
                    Err(error) => Err(NativeError::Cursor(error)),
                }
            }
            Ok(packet) => Ok(Progress::Packet(packet)),
            Err(sequencer::Error::UnqualifiedRetirement) => self.retire(now),
            Err(error) => Err(NativeError::Cursor(error)),
        }
    }
    fn retire(&mut self, now: u64) -> Result<Progress, NativeError> {
        let mut state = self.effects.controller.0.borrow_mut();
        let native = state.native.as_mut().ok_or(NativeError::Unmounted)?;
        let engine = native
            .engine
            .as_mut()
            .ok_or(NativeError::Engine(Error::StaleExecution))?;
        let job = engine
            .job
            .as_ref()
            .filter(|job| job.serial == self.serial)
            .ok_or(NativeError::Engine(Error::StaleExecution))?;
        if !job.completion_action {
            return Err(NativeError::Engine(Error::MissingAction));
        }
        let mut cursor = job.cursor.borrow_mut();
        cursor
            .retire_finalized(job.counted_words)
            .map_err(NativeError::Cursor)?;
        let done = Completion {
            serial: job.serial,
            port: job.port,
            entry: job.entry,
            retired_at: now,
            committed_writes: cursor.committed_writes(),
            committed_reads: cursor.committed_reads(),
        };
        let retained = cursor.control_context();
        drop(cursor);
        engine
            .images
            .get_mut(&done.port)
            .expect("active port")
            .context = retained;
        engine.completed.push(done);
        engine.job = None;
        // Actual accepted command consumed only after its concrete effects and
        // finalized end retired. This is Stela engine state, not a PS snapshot.
        let word = state
            .words
            .get_mut(&(0, Bank::Pmgr, CIO))
            .expect("admitted CIO word");
        word.value &= !((1 << done.port) | (1 << (16 + done.port)));
        Ok(Progress::Retired(done))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
    use crate::platform::apple::{
        bus::{Access, Bus, DeviceId, Lifecycle, LifecycleState, MmioDevice, MmioError},
        interrupt::InterruptLatch,
        pmgr::{
            install::{Action, NativeImage, Outcome, t6000},
            sequencer::{FinishError, copy, poll},
        },
        power::t6000::{Instance, Observation, clock},
    };
    use alloc::boxed::Box;

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        retention: true,
        reset: false,
        quiesced: false,
    };
    const CPM: u64 = 0x28e09c0c0;
    fn program(port: u8) -> Vec<u32> {
        vec![
            0x28e09c01,
            0,
            0x30,
            0, // actual CPM disable input
            0x28e09c02,
            0,
            0x30,
            0x80000000,
            0,            // poll actual CPM input
            4 | (3 << 6), // three actual native cycles
            0x28e09a01,
            0,
            0xd,
            1 << (16 + port), // matching CIO action
            0,                // exact final compiler terminator
        ]
    }
    fn fixture(replace: Option<Vec<u32>>, activate: bool) -> (Controller, Bus, DeviceId) {
        fixture_with_data(replace, activate, None)
    }
    fn fixture_with_data(
        replace: Option<Vec<u32>>,
        activate: bool,
        data: Option<(u64, &[u8])>,
    ) -> (Controller, Bus, DeviceId) {
        let instance = Instance {
            complexes: 1,
            cio_ports: 15,
            cpm_controls: 1,
            isp_clocks: 0,
        };
        let observations = instance
            .offsets(Bank::Pmgr)
            .into_iter()
            .map(|offset| Observation {
                instance: 0,
                bank: Bank::Pmgr,
                offset,
                value: 0,
                known: u32::MAX,
            });
        let owner = Controller::with_native(
            vec![instance],
            LIVE,
            observations,
            super::super::Handoff::StelaEmpty {
                sram: super::super::SramInitialization::Unknown,
            },
        )
        .unwrap();
        let mut bus = Bus::new();
        let controls = bus.add(Box::new(owner.native_controls().unwrap()));
        for row in super::super::controls() {
            bus.map(controls, row.address, 4, row.address).unwrap();
        }
        let sram = bus.add(Box::new(owner.native_sram().unwrap()));
        bus.map(
            sram,
            t6000::SRAM_BASE,
            t6000::SRAM_LIMIT - t6000::SRAM_BASE,
            0,
        )
        .unwrap();
        let requests = bus.add(Box::new(owner.view(0).unwrap()));
        for offset in instance.offsets(Bank::Pmgr) {
            bus.map(requests, 0x28e080000 + offset, 4, offset).unwrap();
        }
        let images = t6000::sequences()
            .into_iter()
            .filter(|row| !row.shared)
            .map(|row| {
                let words = if let Some(port) = [36, 40, 44, 48].iter().position(|id| *id == row.id)
                {
                    replace.clone().unwrap_or_else(|| program(port as u8))
                } else {
                    vec![0xa0000000 | u32::from(row.id), 0]
                };
                NativeImage {
                    sequence: row.id,
                    counted_words: words.len() as u32 - 1,
                    bytes: words.into_iter().flat_map(u32::to_le_bytes).collect(),
                }
            })
            .collect();
        let mut installation = t6000::programs(0x20, Some(0), images).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        while let Some(claim) = installation.begin().unwrap() {
            let outcome = match installation.dispatch(&claim).unwrap() {
                Action::Read { address, width } => {
                    Outcome::<MmioError>::Read(bus.read(address, width, &mut access).unwrap())
                }
                Action::Write(write) => {
                    bus.write(write.address, write.width, write.value, &mut access)
                        .unwrap();
                    Outcome::Written
                }
                Action::DmbSy => panic!("no source barrier in publication"),
            };
            installation.finish(&claim, outcome).unwrap();
        }
        let programs = (0..4)
            .map(|port| Program {
                initial_control: Some(test_initial()),
                port,
                counted_words: replace
                    .as_ref()
                    .map_or_else(|| program(port).len(), Vec::len)
                    as u32
                    - 1,
                format: AddressFormat::HighWord,
            })
            .collect();
        if let Some((address, bytes)) = data {
            // Actual explicit initialization, before the shared native image is
            // frozen for execution. No uninitialized source bytes are supplied.
            owner
                .native_memory()
                .unwrap()
                .write_checked(address, bytes)
                .unwrap();
        }
        owner.bind_cio_engine(programs).unwrap();
        let input = clock::Register::ALL
            .into_iter()
            .map(|register| clock::Observation {
                register,
                value: match register {
                    clock::Register::Pll0Control => (1 << 31) | (1 << 27),
                    clock::Register::Selection => 1 << 31,
                    _ => 0,
                },
                known: u32::MAX,
            })
            .collect();
        owner
            .bind_native_clock(
                clock::Image::new(clock::Input::DeclaredStela(input)).unwrap(),
                clock::Phase::DeclaredStela {
                    at: 0,
                    cycles: 0,
                    fraction: 0,
                },
            )
            .unwrap();
        if activate {
            for address in [0x28e09906c, 0x28e099074] {
                bus.write(address, Width::Word, 1, &mut access).unwrap();
            }
        }
        (owner, bus, requests)
    }
    fn route_write(engine: &mut Engine, bus: &mut Bus, access: &mut Access<'_>) {
        let claim = engine.begin_write().unwrap();
        let write = engine
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        if !engine.commit_controller_write(&claim).unwrap() {
            bus.write(write.address, write.width, write.value, access)
                .unwrap();
            engine
                .finish_write::<()>(&claim, RouteOutcome::Committed)
                .unwrap();
        }
    }
    fn read_poll(engine: &mut Engine, bus: &mut Bus, access: &mut Access<'_>) {
        let claim = engine.begin_read().unwrap();
        let read = engine
            .dispatch_read(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        let value = bus.read(read.address, read.width, access).unwrap();
        assert!(
            engine
                .finish_read::<()>(&claim, poll::Outcome::Read(value))
                .unwrap()
        );
    }

    #[test]
    fn all_four_actual_mounted_requests_execute_shared_sram_and_retire_only_after_action_and_end() {
        for port in 0..4 {
            let (owner, mut bus, requests) = fixture(None, true);
            let mut pins = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut pins);
            bus.write(CIO_ADDRESS, Width::Word, 1 << port, &mut access)
                .unwrap();
            assert_eq!(
                bus.read(CIO_ADDRESS, Width::Word, &mut access),
                Ok((1 << port) | (1 << (16 + port)))
            );
            // Neither another AP request nor a forged AP completion may mutate it.
            assert!(
                bus.write(CIO_ADDRESS, Width::Word, 1 << port, &mut access)
                    .is_err()
            );
            assert!(
                bus.write(CIO_ADDRESS, Width::Word, 1 << (16 + port), &mut access)
                    .is_err()
            );
            let mut engine = owner.cio_engine().unwrap();
            assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Write)));
            route_write(&mut engine, &mut bus, &mut access);
            let pc = engine.packet_pc();
            drop(engine);
            let mut engine = owner.cio_engine().unwrap();
            assert_eq!(engine.packet_pc(), pc);
            assert_eq!(engine.committed_writes(), 1);
            read_poll(&mut engine, &mut bus, &mut access);
            assert_eq!(engine.advance(0), Ok(Progress::Delay { remaining: 3 }));
            assert_eq!(engine.advance(2197), Ok(Progress::Delay { remaining: 1 }));
            assert_eq!(
                engine.advance(2198),
                Ok(Progress::Packet(PacketKind::Write))
            );
            route_write(&mut engine, &mut bus, &mut access);
            assert!(owner.cio_completions().unwrap().is_empty());
            assert_eq!(
                bus.read(CIO_ADDRESS, Width::Word, &mut access),
                Ok((1 << port) | (1 << (16 + port)))
            );
            let Progress::Retired(done) = engine.advance(2198).unwrap() else {
                panic!("actual end");
            };
            assert_eq!(
                (done.port, done.committed_writes, done.committed_reads),
                (port, 2, 1)
            );
            assert_eq!((done.entry.group, done.entry.slot), (4 + port, 2));
            assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
            assert_eq!(owner.cio_completions().unwrap(), vec![done]);
            assert!(matches!(
                owner.cio_engine(),
                Err(NativeError::Engine(Error::NoRequest))
            ));
            bus.device_mut::<super::super::super::View>(requests)
                .unwrap()
                .advance(&mut access)
                .unwrap();
            // A later real transaction is a fresh generation, never a replay.
            bus.write(CIO_ADDRESS, Width::Word, 1 << port, &mut access)
                .unwrap();
            let next = owner.cio_engine().unwrap();
            assert_eq!(next.committed_writes(), 0);
            assert_ne!(next.serial, done.serial);
            assert!(pins.take_aic_inputs().is_empty());
        }
    }

    #[test]
    fn actual_canonical_source_copy_retains_bytes_across_pause_and_destination_refusal() {
        const SOURCE: u64 = t6000::SRAM_BASE + 0x60000;
        const DESTINATION: u64 = 0x1301000000;
        let bytes: Vec<u8> = (0..128).map(|n| (n ^ 0x59) as u8).collect();
        let words = vec![
            (127 << 6) | 8,
            ((SOURCE >> 36) as u32 & 63) | (((DESTINATION >> 36) as u32 & 63) << 16),
            (SOURCE >> 4) as u32 & 0xfffffff8,
            (DESTINATION >> 4) as u32 & 0xfffffff8,
            0xfffffff8, // source's complete pending-copy join
            0x28e09a01,
            0,
            0xd,
            1 << 16, // actual controller action
            0,
        ];
        let (owner, mut bus, requests) =
            fixture_with_data(Some(words), true, Some((SOURCE, &bytes)));
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Copy)));
        let read = engine.begin_copy_read().unwrap();
        let physical = engine
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            physical,
            copy::PhysicalRead {
                address: SOURCE,
                bytes: 128
            }
        );
        let mut actual = vec![0; physical.bytes as usize];
        owner
            .native_memory()
            .unwrap()
            .read_checked(physical.address, &mut actual)
            .unwrap();
        engine
            .finish_copy_read::<()>(&read, copy::ReadOutcome::Read(actual))
            .unwrap();
        assert_eq!(engine.committed_reads(), 1);
        let write = engine.begin_copy_write().unwrap();
        assert_eq!(
            engine
                .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
                .unwrap()
                .bytes(),
            bytes
        );
        // Positive checked destination preflight: no target was touched.
        assert_eq!(
            engine.finish_copy_write(
                &write,
                RouteOutcome::NoEffect("destination reservation unavailable")
            ),
            Err(FinishError::NoEffect("destination reservation unavailable"))
        );
        drop(engine);
        let snapshot = owner
            .native_observations()
            .unwrap()
            .cio_engine
            .unwrap()
            .active
            .unwrap();
        assert_eq!(snapshot.pending_copy.unwrap().phase, copy::Phase::Write);
        assert_eq!(snapshot.committed_reads, 1);
        let mut engine = owner.cio_engine().unwrap();
        let write = engine.begin_copy_write().unwrap();
        let view = bus
            .device_mut::<super::super::super::View>(requests)
            .unwrap();
        let paused = LifecycleState {
            quiesced: true,
            ..LIVE
        };
        view.check_lifecycle(paused).unwrap();
        view.set_lifecycle(paused, &mut access);
        assert_eq!(
            engine.dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap()),
            Err(sequencer::Error::Suspended)
        );
        bus.device_mut::<super::super::super::View>(requests)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        let actual = engine
            .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(actual.address, DESTINATION);
        // A real declared destination reservation, distinct from the canonical
        // immutable native code/source SRAM. Commit follows its actual store.
        let mut destination = vec![0; 128];
        destination.copy_from_slice(actual.bytes());
        engine
            .finish_copy_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(destination, bytes);
        assert_eq!(engine.committed_reads(), 1);
        assert_eq!(engine.committed_writes(), 1);
        assert_eq!(engine.pending_copy().unwrap().phase, copy::Phase::Join);
        assert!(owner.cio_completions().unwrap().is_empty());
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
        assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Write)));
        assert!(engine.pending_copy().is_none());
        assert_eq!(
            engine.last_copy().unwrap().transfer.destination,
            DESTINATION
        );
        route_write(&mut engine, &mut bus, &mut access);
        let Progress::Retired(done) = engine.advance(0).unwrap() else {
            panic!("actual end");
        };
        assert_eq!((done.committed_reads, done.committed_writes), (1, 2));
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn actual_mounted_control_context_changes_survive_pause_and_require_exact_route_acceptance() {
        let words = vec![
            0x30001c, // actual source18000, fields[0,0,0,3,0]
            0x28e09c01,
            0,
            0x30,
            0,    // actual CPM disable
            0x1c, // actual source0, independently updates context
            0x28e09a01,
            0,
            0xd,
            1 << 16,
            0,
        ];
        let (owner, mut bus, requests) = fixture(Some(words), true);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Write)));
        let context = engine.control_context().unwrap();
        assert_eq!(context.fields().values(), [0, 0, 0, 3, 0]);
        let claim = engine.begin_write().unwrap();
        assert_eq!(
            claim.qualify_context(test_fields()).unwrap_err(),
            sequencer::Error::ControlContextRejected
        );
        assert_eq!(engine.committed_writes(), 0);
        // This test route declares one exact accepted context; it does not
        // automatically echo/accept whatever fields the program supplied.
        let accepted = claim
            .qualify_context(sequencer::control::Fields::new([0, 0, 0, 3, 0]).unwrap())
            .unwrap();
        drop(engine);
        let observed = owner
            .native_observations()
            .unwrap()
            .cio_engine
            .unwrap()
            .active
            .unwrap();
        assert_eq!(observed.control_context, Some(context));
        let mut engine = owner.cio_engine().unwrap();
        let paused = LifecycleState {
            clocked: false,
            ..LIVE
        };
        let view = bus
            .device_mut::<super::super::super::View>(requests)
            .unwrap();
        view.check_lifecycle(paused).unwrap();
        view.set_lifecycle(paused, &mut access);
        assert_eq!(
            engine.dispatch_write(&claim, &accepted),
            Err(sequencer::Error::Suspended)
        );
        bus.device_mut::<super::super::super::View>(requests)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        let write = engine.dispatch_write(&claim, &accepted).unwrap();
        bus.write(write.address, write.width, write.value, &mut access)
            .unwrap();
        engine
            .finish_write::<()>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Write)));
        let zero = engine.control_context().unwrap();
        assert_eq!(zero.fields().values(), [0; 5]);
        assert_ne!(zero.generation(), context.generation());
        let action = engine.begin_write().unwrap();
        assert_eq!(
            engine.dispatch_write(&action, &accepted),
            Err(sequencer::Error::StaleControlQualification)
        );
        let accepted = action.qualify_context(test_fields()).unwrap();
        engine.dispatch_write(&action, &accepted).unwrap();
        engine.commit_controller_write(&action).unwrap();
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
        assert!(matches!(engine.advance(0), Ok(Progress::Retired(_))));
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn later_native_job_inherits_actual_retired_context_instead_of_replaying_entry_input() {
        let words = vec![0x30001c, 0x28e09a01, 0, 0xd, 1 << 16, 0];
        let (owner, mut bus, _) = fixture(Some(words), true);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        assert_eq!(engine.control_context().unwrap().fields().values(), [0; 5]);
        engine.advance(0).unwrap();
        let context = engine.control_context().unwrap();
        let claim = engine.begin_write().unwrap();
        let fields = sequencer::control::Fields::new([0, 0, 0, 3, 0]).unwrap();
        let accepted = claim.qualify_context(fields).unwrap();
        engine.dispatch_write(&claim, &accepted).unwrap();
        engine.commit_controller_write(&claim).unwrap();
        assert!(matches!(engine.advance(0), Ok(Progress::Retired(_))));
        assert_eq!(
            owner
                .native_observations()
                .unwrap()
                .cio_engine
                .unwrap()
                .retained_contexts[0],
            (0, Some(context))
        );
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut next = owner.cio_engine().unwrap();
        assert_eq!(next.control_context(), Some(context));
        next.advance(0).unwrap();
        assert_eq!(
            next.control_context().unwrap().generation(),
            context.generation() + 1
        );
        let claim = next.begin_write().unwrap();
        assert_eq!(
            next.dispatch_write(&claim, &accepted),
            Err(sequencer::Error::StaleControlQualification)
        );
    }

    #[test]
    fn stride_packet_retires_each_actual_controller_write_before_cio_end() {
        // Two stores to the same CPM word must remain two ordered effects.
        // This is a declared test program, not an original SRAM observation.
        let words = vec![
            6 | (1 << 6) | (((CPM >> 34) as u32) << 24),
            (CPM >> 2) as u32,
            0,
            0,
            0x28e09a01,
            0,
            0xd,
            1 << 16,
            0,
        ];
        let (owner, mut bus, _) = fixture(Some(words), true);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        let start = engine.packet_pc();
        for index in 0..2 {
            assert_eq!(engine.advance(0), Ok(Progress::Packet(PacketKind::Write)));
            route_write(&mut engine, &mut bus, &mut access);
            assert_eq!(engine.committed_writes(), index + 1);
            assert_eq!(bus.read(CPM, Width::Word, &mut access), Ok(0));
            assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
            if index == 0 {
                assert_eq!(engine.packet_pc(), start);
            }
        }
        assert_eq!(
            owner
                .requests()
                .iter()
                .filter(|request| matches!(
                    request.kind,
                    RequestKind::AutomaticGating { enabled: false, .. }
                ))
                .count(),
            2
        );
        route_write(&mut engine, &mut bus, &mut access);
        let Progress::Retired(done) = engine.advance(0).unwrap() else {
            panic!("actual end");
        };
        assert_eq!(done.committed_writes, 3);
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn partial_external_effect_and_dropped_handle_cannot_ack_or_duplicate_the_store() {
        let (owner, mut bus, _) = fixture(None, true);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        let claim = engine.begin_write().unwrap();
        let actual = engine
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        // Concrete target committed its request, then the physical route lost
        // completion authority. That error must not authorize a second write.
        bus.write(actual.address, actual.width, actual.value, &mut access)
            .unwrap();
        assert_eq!(
            engine.finish_write(&claim, RouteOutcome::Uncertain("after target effect")),
            Err(FinishError::Uncertain("after target effect"))
        );
        drop(engine);
        let mut resumed = owner.cio_engine().unwrap();
        assert_eq!(
            resumed.begin_write().unwrap_err(),
            sequencer::Error::UncertainEffects
        );
        assert_eq!(
            resumed.advance(0),
            Err(NativeError::Cursor(sequencer::Error::UncertainEffects))
        );
        assert_eq!(
            owner
                .requests()
                .iter()
                .filter(|request| matches!(
                    request.kind,
                    RequestKind::AutomaticGating { enabled: false, .. }
                ))
                .count(),
            1
        );
        assert_eq!(bus.read(CPM, Width::Word, &mut access), Ok(0));
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
        assert!(owner.cio_completions().unwrap().is_empty());
    }

    #[test]
    fn action_before_later_effects_retains_in_flight_generation_and_cannot_publish_completion() {
        let words = vec![
            0x28e09a01,
            0,
            0xd,
            1 << 16, // action arrives before later work
            0x28e09c01,
            0,
            0x30,
            0, // actual CPM write still required
            0,
        ];
        let (owner, mut bus, _) = fixture(Some(words), true);
        assert_eq!(
            owner.bind_cio_engine(vec![]),
            Err(NativeError::Engine(Error::Bound))
        );
        let entry = owner.native_entry(4, 2).unwrap();
        assert_eq!(
            owner
                .native_memory()
                .unwrap()
                .write_checked(entry.pc, &[0; 4]),
            Err(NativeError::Pending)
        );
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
        let mut engine = owner.cio_engine().unwrap();
        let action = engine.begin_write().unwrap();
        // A matching public value without dispatch is not an authorized effect.
        assert_eq!(
            engine.commit_controller_write(&action),
            Err(NativeError::Cursor(sequencer::Error::NotDispatched))
        );
        engine
            .dispatch_write(&action, &action.qualify_context(test_fields()).unwrap())
            .unwrap();
        engine.commit_controller_write(&action).unwrap();
        assert!(owner.cio_completions().unwrap().is_empty());
        let claim = engine.begin_write().unwrap();
        drop(engine);
        let snapshot = owner.native_observations().unwrap().cio_engine.unwrap();
        let active = snapshot.active.unwrap();
        assert!(active.completion_action);
        assert_eq!(active.in_flight, Some(false));
        assert_eq!(active.committed_writes, 1);
        let mut engine = owner.cio_engine().unwrap();
        assert_eq!(
            engine.begin_write().unwrap_err(),
            sequencer::Error::InFlight
        );
        let actual = engine
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(
            engine.cancel_write(&claim),
            Err(sequencer::Error::AlreadyDispatched)
        );
        // Positively proved no-effect preflight allows a new exclusive ticket.
        assert_eq!(
            engine.finish_write(&claim, RouteOutcome::NoEffect("checked route preflight")),
            Err(FinishError::NoEffect("checked route preflight"))
        );
        assert_eq!(
            engine.dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
            Err(sequencer::Error::StaleClaim)
        );
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
        route_write(&mut engine, &mut bus, &mut access);
        assert_eq!(actual.address, CPM);
        let Progress::Retired(done) = engine.advance(0).unwrap() else {
            panic!("real final end");
        };
        assert_eq!(done.committed_writes, 2);
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
        assert_eq!(
            engine.advance(0),
            Err(NativeError::Engine(Error::StaleExecution))
        );
        assert_eq!(
            owner
                .native_memory()
                .unwrap()
                .write_checked(entry.pc, &[0; 4]),
            Err(NativeError::Pending)
        );
    }

    #[test]
    fn unknown_instruction_early_end_missing_action_and_unactivated_request_preserve_real_pending_state()
     {
        for (words, expected) in [
            (
                vec![0x10, 0],
                NativeError::Cursor(sequencer::Error::UnqualifiedInstruction(0x10)),
            ),
            (vec![0], NativeError::Engine(Error::MissingAction)),
            (
                vec![0x28e09a01, 0, 0xd, 1 << 16, 0, 4, 0],
                NativeError::Cursor(sequencer::Error::FinalizedExtent),
            ),
        ] {
            let (owner, mut bus, _) = fixture(Some(words), true);
            let mut pins = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut pins);
            bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
            let mut engine = owner.cio_engine().unwrap();
            if engine.packet_kind() == Ok(PacketKind::Write) {
                route_write(&mut engine, &mut bus, &mut access);
            }
            assert_eq!(engine.advance(0), Err(expected));
            assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0x10001));
            assert!(owner.cio_completions().unwrap().is_empty());
        }
        let (owner, mut bus, _) = fixture(None, false);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        assert!(bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).is_err());
        assert!(owner.requests().is_empty());
        assert_eq!(bus.read(CIO_ADDRESS, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn retained_clock_power_and_quiesce_keep_the_actual_job_and_distinct_delay_progress() {
        for pause in 0..3 {
            let (owner, mut bus, requests) = fixture(None, true);
            let mut pins = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut pins);
            bus.write(CIO_ADDRESS, Width::Word, 1, &mut access).unwrap();
            let mut engine = owner.cio_engine().unwrap();
            route_write(&mut engine, &mut bus, &mut access);
            read_poll(&mut engine, &mut bus, &mut access);
            assert_eq!(engine.advance(0), Ok(Progress::Delay { remaining: 3 }));
            let mut paused = LIVE;
            match pause {
                0 => paused.clocked = false,
                1 => paused.powered = false,
                _ => paused.quiesced = true,
            }
            let view = bus
                .device_mut::<super::super::super::View>(requests)
                .unwrap();
            view.check_lifecycle(paused).unwrap();
            view.set_lifecycle(paused, &mut access);
            assert_eq!(
                engine.advance(3000),
                Err(NativeError::Cursor(sequencer::Error::Suspended))
            );
            access.now = 3000;
            bus.device_mut::<super::super::super::View>(requests)
                .unwrap()
                .set_lifecycle(LIVE, &mut access);
            if pause == 2 {
                assert_eq!(
                    engine.advance(3000),
                    Ok(Progress::Packet(PacketKind::Write))
                );
            } else {
                assert_eq!(engine.advance(3000), Ok(Progress::Delay { remaining: 3 }));
                assert_eq!(
                    engine.advance(5198),
                    Ok(Progress::Packet(PacketKind::Write))
                );
            }
            route_write(&mut engine, &mut bus, &mut access);
            assert!(matches!(engine.advance(5198), Ok(Progress::Retired(_))));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires original J314s LLB/iBootData and mac13j kernelcache"]
    fn original_cio_request_wait_bindings_actions_and_counted_finalization_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
        let kernel =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
        for (bytes, digest) in [
            (
                &llb,
                "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
            ),
            (
                &kernel,
                "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
            ),
            (
                &data,
                "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(bytes)), digest);
        }
        for (bytes, lo, hi, digest) in [
            (
                &llb,
                0x471b8,
                0x47a58,
                "a3e8016b0e7d3b04350d32af963f656ea62303d6c1a3fcad29eeae2a80216ec8",
            ),
            (
                &llb,
                0x106a0,
                0x10804,
                "68af9728e5cd5b740fa7d66040b8b429d995d6626d51dc2d7945ba0bf4e20553",
            ),
            (
                &llb,
                0x113e8,
                0x11660,
                "6e6c9388dd1bddd152f22e7f9072cccf73de57320a90da253beaa36193806681",
            ),
            (
                &kernel,
                0x2f0a720,
                0x2f0a7cc,
                "ecb38e666ddf93722fcd583727c128759fe77b12a074865893d7c9849b3fa5cc",
            ),
            (
                &kernel,
                0x2b4affc,
                0x2b4b1ec,
                "8cded4ff1c9695ad0cf835cb88ceb3326bb33e11e7ab3d52f3c5bb8271cbfdf5",
            ),
            (
                &data,
                0x4000,
                0x6bf08,
                "20975d766b7d5bc14ee81c764073359d80fdae6e276523b3f7055e1957ca8e76",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&bytes[lo..hi])), digest);
        }
        // The source ends each corresponding CIO sequence by a real write to
        // the request/status word, not by returning a software success value.
        for (port, offset) in [0x57ac0, 0x58090, 0x58660, 0x58c78].into_iter().enumerate() {
            let row = &data[offset..offset + 24];
            assert_eq!(
                u16::from_le_bytes(row[..2].try_into().unwrap()),
                36 + port as u16 * 4
            );
            assert_eq!(u16::from_le_bytes(row[2..4].try_into().unwrap()), 0x20);
            assert_eq!(
                u64::from_le_bytes(row[8..16].try_into().unwrap()),
                CIO_ADDRESS
            );
            assert_eq!(
                u64::from_le_bytes(row[16..24].try_into().unwrap()),
                1 << (16 + port)
            );
        }
        let word = |bytes: &[u8], offset| {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        };
        assert_eq!(word(&kernel, 0x2b4b0fc), 0x6a15001f); // TST actual read/mask
        assert_eq!(word(&kernel, 0x2b4b100), 0x54000500); // exit when high bit CLEAR
        assert_eq!(word(&llb, 0x11574), 0xb8286abf); // actual zero terminator store
        assert_eq!(word(&llb, 0x115b8), 0x6b0802bf); // compare counted/emitted words
        // A control instruction exists even with source control0. Its actual
        // flag/handshake effects are deliberately not treated as a no-op.
        assert_eq!(word(&llb, 0x107c8), 0x321e0929);
    }
}
