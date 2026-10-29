//! Stela-native CIO execution over the canonical T6000 SRAM.
//!
//! LLB471b8 binds the four CIO groups to the shared slot at28e099068.
//! Original RCfg36/40/44/48 publish their corresponding high-bit action to
//!28e09a034. The kernel's matching request/wait pair is2f0a720/2b4b084.
//! This engine executes supplied, finalized programs; it is not a capture of
//! Apple's hidden micro-PC, cold state, or unimplemented control instructions.
use super::{Controller, Entry, Error as NativeError, effects::Effects};
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::{
    cell::RefCell,
    ops::{Deref, DerefMut},
};
use {
    crate::platform::apple::pmgr::sequencer,
    crate::platform::apple::pmgr::sequencer::AddressFormat,
    crate::platform::apple::pmgr::sequencer::PacketCursor,
    crate::platform::apple::pmgr::sequencer::PacketKind,
    crate::platform::apple::pmgr::sequencer::RouteOutcome,
    crate::platform::apple::pmgr::sequencer::WriteClaim,
    crate::platform::apple::power::t6000::Bank, crate::platform::apple::power::t6000::CIO,
    crate::platform::apple::power::t6000::RequestKind, stela_contracts::bus::Width,
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

/// Compiler finalization metadata, supplied before accepting requests.
/// Bytes are read from the same physically installed SRAM, never this input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    /// First-entry permission only. Later jobs inherit their kept
    /// Stela port context; a capture/declaration is never replayed as a reset.
    /// None keeps unknown context until a real tag1c executes.
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

/// A handle to the controller-owned job; dropping it keeps the cursor and
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
    /// Bind one complete admitted CIO program family after publication.
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

    /// Start/resume the oldest accepted request. The job owns its PC,
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
        // inputs never become ready because a pointer is installed.
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
    /// Commit the source's high-bit CIO action through its controller
    /// owner. Only a dispatched claim of this job can submit it. Ordinary AP
    /// writes have no such permission. Other physical targets return false and
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
        // Accepted command consumed only after its concrete effects and
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
mod tests;
