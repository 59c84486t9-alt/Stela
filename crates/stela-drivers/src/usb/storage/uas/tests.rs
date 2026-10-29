// SPDX-License-Identifier: GPL-2.0-only
//! Shared UAS transport, target, DMA and clock fixtures.
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::{rc::Rc, vec};
use core::cell::{Cell, RefCell};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    WrongReady,
    WrongTag,
    MalformedStatus,
    ShortCommand,
    ShortData,
    Timeout,
    SubmitStatus,
    SubmitCommand,
    ErrorAfterReady,
    CancelError,
    StatusBeforeData,
    FlushError,
    CommandLast,
    SubmitData,
    EndpointUnavailable,
}
#[derive(Clone, Copy)]
struct Ticket {
    pipe: Pipe,
    id: u64,
    address: u64,
    length: usize,
    stream: u16,
}
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Post(Pipe),
    Complete(Pipe),
    Cancel(Pipe),
}
struct State {
    range: core::ops::Range<u64>,
    events: Vec<Event>,
    active: Vec<Ticket>,
    next: u64,
    command: Option<Vec<u8>>,
    history: Vec<Vec<u8>>,
    tag: u16,
    requested: usize,
    input: bool,
    ready: bool,
    data_done: bool,
    terminal_sent: bool,
    fault: Fault,
    written: Vec<u8>,
    target: Option<Target>,
    reply: Option<Reply>,
    streams: Option<u16>,
}
#[derive(Clone)]
struct Model {
    state: Rc<RefCell<State>>,
    clock: Rc<Cell<u64>>,
}
impl Model {
    fn bytes(s: &State, t: &Ticket) -> Vec<u8> {
        assert!(t.address >= s.range.start && t.address + t.length as u64 <= s.range.end);
        // SAFETY: one test owns this live DMA range, and only its synchronous
        // completion model accesses it until the ticket is retired.
        unsafe { core::slice::from_raw_parts(t.address as *const u8, t.length) }.to_vec()
    }
    fn write(s: &State, t: &Ticket, bytes: &[u8]) {
        assert!(
            bytes.len() <= t.length
                && t.address >= s.range.start
                && t.address + t.length as u64 <= s.range.end
        );
        // SAFETY: as bytes(); every write is within this ticket's allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), t.address as *mut u8, bytes.len());
        }
    }
}

fn model(memory: &mut [u64], length: usize, input: bool, fault: Fault) -> (Model, RegionAllocator) {
    let start = memory.as_mut_ptr() as u64;
    let range = start..start + core::mem::size_of_val(memory) as u64;
    let io = Model {
        state: Rc::new(RefCell::new(State {
            range: range.clone(),
            events: Vec::new(),
            active: Vec::new(),
            next: 0,
            command: None,
            history: Vec::new(),
            tag: 0,
            requested: length,
            input,
            ready: false,
            data_done: false,
            terminal_sent: false,
            fault,
            written: Vec::new(),
            target: None,
            reply: None,
            streams: None,
        })),
        clock: Rc::new(Cell::new(0)),
    };
    // SAFETY: each test keeps memory exclusive/live until all IO owners drop.
    (io, unsafe { RegionAllocator::new(range) })
}
#[derive(Clone)]
struct Media {
    lun: Lun,
    blocks: u64,
    block_size: u32,
    read_only: bool,
    empty: bool,
    marker: u8,
    version: u8,
}
impl Media {
    fn disk(lun: Lun, marker: u8) -> Self {
        Self {
            lun,
            blocks: 4096,
            block_size: 512,
            read_only: false,
            empty: false,
            marker,
            version: 6,
        }
    }
}
struct Reply {
    requested: usize,
    input: bool,
    data: Vec<u8>,
    sense: Option<u32>,
    wrong_tag: bool,
}
enum CacheReply {
    Replace {
        sense: u32,
        blocks: u64,
        read_only: bool,
    },
    Sense(u32),
    Data(Vec<u8>),
}
struct Target {
    media: Vec<Media>,
    reported: Vec<Lun>,
    report_override: Option<Vec<u8>>,
    report_attention: usize,
    unit_attention: Option<u32>,
    report_change_blocks: Option<u64>,
    block_zero_change: Option<(Lun, u64)>,
    cache_reply: Option<CacheReply>,
    report_illegal: bool,
    poison_lun: Option<Lun>,
    writes: Vec<(Lun, u64, Vec<u8>)>,
    flushes: Vec<Lun>,
}

struct ScsiModel {
    engine: Engine<Model>,
    flags: quirks::Flags,
}

fn target_owner(
    memory: &mut [u64],
    target: Target,
    flags: quirks::Flags,
) -> (Rc<RefCell<ScsiModel>>, Rc<RefCell<State>>) {
    let (io, mut dma) = model(memory, 0, false, Fault::None);
    let state = io.state.clone();
    state.borrow_mut().target = Some(target);
    (
        Rc::new(RefCell::new(ScsiModel {
            engine: Engine::new(io, &mut dma).unwrap(),
            flags,
        })),
        state,
    )
}

impl Target {
    fn new(media: Vec<Media>) -> Self {
        Self {
            reported: media.iter().map(|m| m.lun).collect(),
            media,
            report_override: None,
            report_attention: 0,
            unit_attention: None,
            report_change_blocks: None,
            block_zero_change: None,
            cache_reply: None,
            report_illegal: false,
            poison_lun: None,
            writes: Vec::new(),
            flushes: Vec::new(),
        }
    }

    fn range(cdb: &[u8]) -> (u64, u32) {
        if matches!(cdb[0], 0x28 | 0x2a) {
            (
                u64::from(u32::from_be_bytes(cdb[2..6].try_into().unwrap())),
                u32::from(u16::from_be_bytes(cdb[7..9].try_into().unwrap())),
            )
        } else {
            (
                u64::from_be_bytes(cdb[2..10].try_into().unwrap()),
                u32::from_be_bytes(cdb[10..14].try_into().unwrap()),
            )
        }
    }
}

fn rw(input: bool, length: usize) -> [u8; 10] {
    let mut cdb = [0; 10];
    cdb[0] = if input { 0x28 } else { 0x2a };
    cdb[5] = 1;
    cdb[7..9].copy_from_slice(&((length / 512) as u16).to_be_bytes());
    cdb
}

fn write_form(op: u8, action: Option<u16>, fua: bool) -> Vec<u8> {
    let length = match op {
        0x2a | 0x2e => 10,
        0xaa | 0xae => 12,
        0x7f => 32,
        _ => 16,
    };
    let mut cdb = vec![0; length];
    cdb[0] = op;
    if op == 0x7f {
        cdb[7] = 24;
        cdb[8..10].copy_from_slice(&action.unwrap().to_be_bytes());
        cdb[10] = if fua { 8 } else { 0 };
        cdb[28..32].copy_from_slice(&1u32.to_be_bytes());
    } else {
        cdb[1] = if fua { 8 } else { 0 };
        match op {
            0x2a | 0x2e => cdb[7..9].copy_from_slice(&1u16.to_be_bytes()),
            0xaa | 0xae => cdb[6..10].copy_from_slice(&1u32.to_be_bytes()),
            0x9c => cdb[12..14].copy_from_slice(&1u16.to_be_bytes()),
            _ => cdb[10..14].copy_from_slice(&1u32.to_be_bytes()),
        };
    }
    cdb
}

mod block_zero;
mod cache_policy;
mod command_forms;
mod discovery;
mod io;
mod linux_oracle;
mod media_changes;
mod native_admission;
mod native_rescan;
mod native_reset;
mod retirement;
mod scsi;
mod streams;
mod target;
mod transport_data;
mod transport_errors;
