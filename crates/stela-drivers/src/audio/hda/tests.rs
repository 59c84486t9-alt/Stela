// SPDX-License-Identifier: GPL-2.0-only
//! Shared controller test fixtures for command rings, codecs and PCM DMA.
use super::*;
use crate::{
    audio::{Direction, PcmFormat},
    bus::dma::RegionAllocator,
};
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
mod composition;
mod lifecycle;
mod realtek_owned_models;
mod unsolicited_models;

#[derive(Clone)]
struct ModelClock(Rc<Cell<u64>>);
impl Timer for ModelClock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 1);
    }
}

struct Fixture {
    _backing: Vec<u64>,
    allocator: RegionAllocator,
}
impl Fixture {
    fn new() -> Self {
        let mut backing = vec![0u64; 256 * 1024];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: unique vector-backed RAM outlives the controller and all DMA.
        let allocator = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        Self {
            _backing: backing,
            allocator,
        }
    }
}

mod model;
use model::*;

struct ResetPciState {
    words: [u32; 64],
    writes: Vec<(u32, u64, u8, bool)>,
    reject_disable: bool,
    reject_enable: bool,
    failed_read: u8,
    reads: usize,
    clock_reads: usize,
}
impl Default for ResetPciState {
    fn default() -> Self {
        Self {
            words: [0; 64],
            writes: Vec::new(),
            reject_disable: false,
            reject_enable: false,
            failed_read: 0,
            reads: 0,
            clock_reads: 0,
        }
    }
}
struct ResetPci {
    model: Rc<RefCell<Model>>,
    gate: Rc<Cell<bool>>,
    state: Rc<RefCell<ResetPciState>>,
    clock: ModelClock,
}
impl crate::bus::pci::ConfigSpace for ResetPci {
    fn read32(&self, offset: u16) -> u32 {
        let mut s = self.state.borrow_mut();
        s.reads += 1;
        if offset == 0x48 {
            s.clock_reads += 1;
        }
        if offset == 0x48
            && (s.failed_read == 1
                || (s.failed_read == 2 && s.writes.iter().any(|(v, ..)| v & 0x40 == 0))
                || (s.failed_read == 3 && s.writes.iter().any(|(v, ..)| v & 0x40 != 0)))
        {
            return u32::MAX;
        }
        s.words[usize::from(offset / 4)]
    }
    fn write32(&mut self, offset: u16, value: u32) {
        assert_eq!(offset, 0x48);
        let mut s = self.state.borrow_mut();
        let model = self.model.borrow();
        s.writes.push((
            value,
            self.clock.now_us(),
            model.link_initializations,
            model.get(CORBCTL, 1) & u32::from(COMMAND_RUN) != 0,
        ));
        if (value & 0x40 == 0 && s.reject_disable) || (value & 0x40 != 0 && s.reject_enable) {
            return;
        }
        s.words[usize::from(offset / 4)] = value;
        self.gate.set(value & 0x40 != 0);
    }
}
fn reset_pci(
    model: &Rc<RefCell<Model>>,
) -> (
    crate::bus::pci::Function<ResetPci>,
    Rc<RefCell<ResetPciState>>,
) {
    let mut state = ResetPciState::default();
    state.words[0] = 0xa170_8086;
    state.words[2] = 0x0403_0000;
    state.words[4] = 0xfebf_0000;
    state.words[18] = 0xa5a5_00c3;
    let state = Rc::new(RefCell::new(state));
    let gate = Rc::new(Cell::new(true));
    model.borrow_mut().reset_gate = Some(gate.clone());
    let function = crate::bus::pci::Function::new(
        crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 27,
            function: 0,
        },
        ResetPci {
            model: model.clone(),
            gate,
            state: state.clone(),
            clock: model.borrow().clock.clone(),
        },
    )
    .unwrap();
    (function, state)
}
fn extended_model() -> Rc<RefCell<Model>> {
    with_extended(graph_model())
}
fn with_extended(model: Rc<RefCell<Model>>) -> Rc<RefCell<Model>> {
    {
        let mut m = model.borrow_mut();
        m.bytes.resize(0x2000, 0);
        m.set(0x14, 0x500, 2);
        for (offset, value) in [
            (0x500, 0x1001_0800), //GTS ->PP, one known global counter unit.
            (0x800, 0x1003_0c00), //PP ->ML.
            (0xc00, 0x1002_0700), //ML ->SPB.
            (0xc04, 1),           //Two conventional HDA links.
            (0xc40, 0x3f),
            (0xc44, (1 << 16) | (1 << 23)), //First link6MHz.
            (0xc80, 0x3f),
            (0xc84, 3 | (1 << 16) | (1 << 23)), //Second48MHz untouched.
            (0x700, 0x1004_1000),               //SPB ->DRSM.
            (0x1000, 0x1005_0000),
        ] {
            m.set(offset, value, 4);
        }
        m.link_controls = vec![0xc44, 0xc84];
    }
    model
}

fn modern_config() -> Config {
    Config {
        reset_policy: ResetPolicy::IntelClockGate,
        stream_tag_policy: StreamTagPolicy::PerDirection,
        ..config()
    }
}

type Host = Controller<ModelRegisters, ModelClock>;
fn config() -> Config {
    Config {
        transition_timeout_us: 50,
        verb_timeout_us: 30,
        ..Config::default()
    }
}
fn create(
    model: &Rc<RefCell<Model>>,
    fixture: &mut Fixture,
    config: Config,
) -> Result<Host, Error> {
    let timer = model.borrow().clock.clone();
    // SAFETY: model is the only device owner, DMA fixture stays alive in tests.
    unsafe {
        Controller::new(
            ModelRegisters(model.clone()),
            timer,
            &mut fixture.allocator,
            config,
        )
    }
}
fn verb() -> Verb {
    Verb::short(0, 0, 0xf00, 0).unwrap()
}
fn pcm() -> PcmFormat {
    PcmFormat {
        rate: 48_000,
        bits: 16,
        channels: 2,
    }
}
fn advance(model: &Rc<RefCell<Model>>, microseconds: u64) {
    for _ in 0..microseconds {
        let mut m = model.borrow_mut();
        m.clock.relax();
        m.advance();
    }
}

fn graph_model() -> Rc<RefCell<Model>> {
    let model = Model::new(16);
    {
        let mut m = model.borrow_mut();
        m.constant_reply = None;
        for (node, parameter, value) in [
            (0, 0, 0x1234_5678),
            (0, 2, 0x0010_0100),
            (0, 4, (1 << 16) | 1),
            (1, 5, 1),
            (1, 0x0f, 1),
            (1, 4, (2 << 16) | 6),
            (1, 0x0a, (1 << 6) | (1 << 17)),
            (1, 0x0b, 1),
            (1, 0x0d, 0x8000_1234),
            (1, 0x12, 0x8000_5678),
            (2, 9, 1 | (1 << 2)), // stereo output, inherited output amp/PCM
            (3, 9, (1 << 20) | 1 | (1 << 8)),
            (3, 0x0e, 1),
            (4, 9, (4 << 20) | (1 << 8)),
            (4, 0x0e, 0x81),
            (4, 0x0c, 0x10),
            (5, 9, 4 << 20),
            (5, 0x0c, 0x20),
            (6, 9, (2 << 20) | (1 << 8)),
            (6, 0x0e, 2),
            (7, 9, (3 << 20) | (1 << 8)),
            (7, 0x0e, 0x82),
        ] {
            m.parameters.insert((node, parameter), value);
        }
        m.connection_words.insert((3, 0), 5);
        m.connection_words.insert((4, 0), 2); // long list
        m.connection_words.insert((6, 0), 2 | (0x84 << 8)); // short range2..4
        m.connection_words.insert((7, 0), 2 | (0x8004 << 16)); // long range2..4
    }
    model
}

fn analog_model() -> Rc<RefCell<Model>> {
    let model = graph_model();
    {
        let mut m = model.borrow_mut();
        m.parameters.insert((1, 0x0d), 0x8000_1f1f);
        m.parameters.insert((1, 0x12), 0x8000_1f1f);
        for (node, parameter, value) in [
            (2, 9, 1 | (1 << 2) | (1 << 10)),
            (2, 0x0f, 1),
            (3, 9, (1 << 20) | 1 | (1 << 1) | (1 << 8)),
            (4, 9, (4 << 20) | 1 | (1 << 2) | (1 << 8)),
            (4, 0x0c, 0x18 | (1 << 16)),
            (5, 9, (4 << 20) | 1 | (1 << 1)),
            (5, 0x0c, 0x20 | (0x37 << 8)),
            (6, 9, (2 << 20) | 1 | (1 << 1) | (1 << 2) | (1 << 8)),
            (7, 9, (3 << 20) | 1 | (1 << 8)),
            (7, 0x0e, 2),
        ] {
            m.parameters.insert((node, parameter), value);
        }
        m.connection_words.insert((4, 0), 7);
        m.connection_words.insert((6, 0), 2 | (3 << 8));
        m.connection_words.insert((7, 0), 6 | (2 << 8));
        m.route_controls.insert((4, 0xf0c), 5); // Preserve BTL and L/R bits.
    }
    model
}

fn stereo() -> PcmFormat {
    PcmFormat {
        rate: 48_000,
        bits: 16,
        channels: 2,
    }
}

fn retry_config(attempts: u8) -> Config {
    Config {
        probe_policy: ProbePolicy::Retry {
            attempts,
            delay_us: 80,
        },
        ..config()
    }
}

fn access_counts(model: &Rc<RefCell<Model>>) -> (usize, usize, usize) {
    let m = model.borrow();
    (m.reads, m.writes.len(), m.commands.len())
}

fn realtek_desktop_model(id: u32) -> Rc<RefCell<Model>> {
    let model = analog_model();
    {
        let mut m = model.borrow_mut();
        m.parameters.insert((0, 0), id);
        m.parameters.insert((1, 4), (2 << 16) | 31);
        m.parameters.insert((0x20, 9), (15 << 20) | (1 << 6));
        for index in [4, 7, 10] {
            m.coefficients.insert((0x20, index), u16::MAX);
        }
    }
    model
}

fn realtek_headphone_model(id: u32, present: bool) -> Rc<RefCell<Model>> {
    let model = realtek_desktop_model(id);
    {
        let mut m = model.borrow_mut();
        m.pin_defaults.insert(4, 0x0221_4030);
        m.pin_senses.insert(4, if present { 1 << 31 } else { 0 });
        m.parameters.insert((4, 0x0c), 0x1001c);
        *m.parameters.get_mut(&(4, 9)).unwrap() |= 1 << 10;
        m.parameters.insert((4, 0x0f), 1);
        m.coefficients.insert((0x20, 0x10), 0xa7ff);
    }
    model
}

fn realtek_two_sense_model(id: u32, first: bool, second: bool) -> Rc<RefCell<Model>> {
    let model = realtek_headphone_model(id, first);
    {
        let mut m = model.borrow_mut();
        m.parameters.insert((0x16, 9), (4 << 20) | 0x10d);
        // PIN_OUT and AMP_OUT_UNMUTE require neither HP_EN nor mute support.
        m.parameters.insert((0x16, 0x0c), 0x15);
        m.parameters.insert((0x16, 0x12), 0x1f1f);
        m.parameters.insert((0x16, 0x0e), 1);
        m.parameters.insert((8, 9), 5);
        m.connection_words.insert((0x16, 0), 8);
        m.pin_defaults.insert(0x16, 0x4111_11f0); // Actual NoConnection.
        m.pin_senses
            .insert(0x16, if second { 0x8000_0123 } else { 0x123 });
        for (index, value) in [
            (0, 0),
            (0x38, 0xab7f),
            (0x0d, 0xb7ff),
            (0x36, 0xaaff),
            (0x67, 0xdead),
            (0x4a, 0x2fff),
        ] {
            m.coefficients.insert((0x20, index), value);
        }
        m.coefficients.insert((0x58, 3), 0xa53f);
        m.coefficients.insert((0x57, 4), 0xab07);
        m.depop_delay_us = Some(100_000);
        m.depop_mutate_saved = true;
    }
    model
}

fn headphone_binding(route: &AnalogRoute, stream: StreamId) -> RealtekHeadphoneRoute<'_> {
    RealtekHeadphoneRoute {
        route,
        stream,
        channel: 0,
        options: PinOptions::Playback {
            headphone: true,
            eapd: None,
        },
    }
}

mod cirrus;
mod conexant;
mod reset;
mod sigmatel;

mod links;

mod commands;

mod codec_graph;

mod streams;

mod discovery;

mod realtek_dual_headphone;

mod realtek_fixed_headphone;

mod realtek_alc298;

mod realtek_alc269;

mod realtek_common;

mod analog_routes;

mod register_failures;

mod dma_positions;

mod controller_identity;
