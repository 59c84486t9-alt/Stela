// SPDX-License-Identifier: GPL-2.0-only
//! composition controller-model tests.
use super::*;
use crate::bus::pci::{Address, Bar, ConfigSpace, Function};

// A separate numeric PCI model wraps the existing actual CORB/RIRB/BDL
// device, so vendor verbs cannot be replaced by fabricated private State.
struct PciState {
    words: [u32; 64],
    model: Rc<RefCell<Model>>,
    writes: Vec<(u16, u32, u64)>,
    d0_ready: u64,
    reject_d3: bool,
}
struct PciModel(Rc<RefCell<PciState>>);
impl PciModel {
    fn write(&mut self, offset: u16, bytes: u8, value: u32) {
        let mut state = self.0.borrow_mut();
        let model = state.model.borrow();
        let now = model.clock.now_us();
        if offset == 0x54 {
            assert_eq!(bytes, 2);
            assert_eq!(state.words[1] & 6, 0, "PCI decode/master before PM");
            assert_eq!(model.get(0x4c, 1) & 2, 0, "CORB before PM");
            assert_eq!(model.get(0x5c, 1) & 2, 0, "RIRB before PM");
            if value & 3 == 3 || state.words[0x54 / 4] & 3 == 3 {
                assert_eq!(model.get(8, 4) & 1, 0, "link before PM");
            }
            for index in 0..4 {
                assert_eq!(model.get(0x80 + index * 0x20, 1) & 2, 0);
            }
            if value & 3 == 3 {
                // This fixture's actual ALC662-family EAPD pin and PCM pin
                // must both be quiet before PCI power can change.
                assert_eq!(model.route_controls[&(0x14, 0xf0c)], 0);
                assert_eq!(model.route_controls[&(4, 0xf07)], 0);
                let eapd_off = model
                    .command_times
                    .iter()
                    .rev()
                    .find(|(command, _)| *command == 0x0147_0c00)
                    .unwrap()
                    .1;
                assert!(now >= eapd_off + 200_000, "actual family depop delay");
            }
        }
        drop(model);
        state.writes.push((offset, value, now));
        if offset == 0x54 {
            if value & 3 == 3 && state.reject_d3 {
                return;
            }
            let old = state.words[0x54 / 4];
            // PME status is W1C. D3hot->D0 has an actual 10ms readiness
            // boundary even though this model retains BAR contents.
            if old & 3 == 3 && value & 3 == 0 {
                state.d0_ready = now + 10_000;
            }
            state.words[0x54 / 4] = value & !0x8000 | (old & !value & 0x8000);
            return;
        }
        let shift = (offset & 3) * 8;
        let mask = if bytes == 4 {
            u32::MAX
        } else {
            (1 << (bytes * 8)) - 1
        };
        let word = &mut state.words[usize::from(offset / 4)];
        *word = *word & !(mask << shift) | (value & mask) << shift;
    }
}
impl ConfigSpace for PciModel {
    fn read32(&self, offset: u16) -> u32 {
        self.0.borrow().words[usize::from(offset / 4)]
    }
    fn write32(&mut self, offset: u16, value: u32) {
        self.write(offset, 4, value);
    }
    fn write16(&mut self, offset: u16, value: u16) {
        self.write(offset, 2, u32::from(value));
    }
    fn write8(&mut self, offset: u16, value: u8) {
        self.write(offset, 1, u32::from(value));
    }
}
struct PoweredRegisters {
    inner: ModelRegisters,
    pci: Rc<RefCell<PciState>>,
}
impl PoweredRegisters {
    fn check(&self) {
        let state = self.pci.borrow();
        assert_eq!(state.words[0x54 / 4] & 3, 0, "BAR in D3hot");
        assert_ne!(state.words[1] & 2, 0, "BAR without decode");
        assert!(state.model.borrow().clock.now_us() >= state.d0_ready);
    }
}
impl Registers for PoweredRegisters {
    fn region_bytes(&self) -> usize {
        self.inner.region_bytes()
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.check();
        self.inner.read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.check();
        self.inner.read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.check();
        self.inner.read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.check();
        self.inner.write8(offset, value);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.check();
        self.inner.write16(offset, value);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.check();
        self.inner.write32(offset, value);
    }
}
type Hardware = (
    Rc<RefCell<Model>>,
    Function<PciModel>,
    Rc<RefCell<PciState>>,
);
type NativeController<'a> =
    Controller<pci::PciRegisters<'a, PoweredRegisters, PciModel>, ModelClock>;

fn hardware() -> Hardware {
    let model = realtek_desktop_model(0x10ec_0662);
    {
        let mut m = model.borrow_mut();
        m.parameters.insert((0, 2), 0x100300);
        m.parameters.insert((0x14, 9), (4 << 20) | 1);
        m.parameters.insert((0x14, 0x0c), 0x10010);
        m.pin_defaults.insert(0x14, 0x0101_4010);
    }
    let mut words = [0; 64];
    words[0] = 0x2668_8086;
    words[1] = 0x0010_0406;
    words[2] = 0x0403_0001;
    words[4] = 0xfebf_0000;
    words[11] = 0x1234_abcd;
    words[13] = 0x50;
    words[0x44 / 4] = 7;
    words[0x50 / 4] = 0x0003_0001;
    words[0x54 / 4] = 0x8000;
    let state = Rc::new(RefCell::new(PciState {
        words,
        model: model.clone(),
        writes: Vec::new(),
        d0_ready: 0,
        reject_d3: false,
    }));
    let function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 27,
            function: 0,
        },
        PciModel(state.clone()),
    )
    .unwrap();
    (model, function, state)
}
fn claim<'a>(
    function: &'a mut Function<PciModel>,
    state: &Rc<RefCell<PciState>>,
    fixture: &mut Fixture,
) -> NativeController<'a> {
    let model = state.borrow().model.clone();
    let clock = model.borrow().clock.clone();
    // SAFETY: isolated exclusive symbolic PCI/BAR owner, actual retained
    // model RAM, no firmware/DSP and one matching conventional function.
    let registers = unsafe {
        pci::prepare_with_registers(
            function,
            Bar::Memory {
                address: 0xfebf_0000,
                size: 0x4000,
                prefetchable: false,
                wide: false,
            },
            &clock,
            pci::Ownership::ExclusiveLegacy,
            PoweredRegisters {
                inner: ModelRegisters(model),
                pci: state.clone(),
            },
        )
    }
    .unwrap();
    let config = registers.config();
    // SAFETY: same retained symbolic function, BAR and unique DMA RAM.
    unsafe { Controller::new(registers, clock, &mut fixture.allocator, config) }.unwrap()
}
fn routes<R: Registers, T: Timer>(
    c: &mut Controller<R, T>,
    fixture: &mut Fixture,
) -> (CodecGraph, StreamId, StreamId) {
    let graph = c.enumerate_codec(0).unwrap();
    assert_eq!(
        c.initialize_realtek_codec(&graph).unwrap().family,
        RealtekFamily::Alc662
    );
    let out = c
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let input = c
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let capture = graph.analog_route(Direction::Capture, 5, 3).unwrap();
    c.configure_analog_route(
        &graph,
        &output,
        out,
        0,
        PinOptions::Playback {
            headphone: false,
            eapd: Some(true),
        },
    )
    .unwrap();
    c.configure_analog_route(
        &graph,
        &capture,
        input,
        0,
        PinOptions::Capture {
            vref: Vref::EightyPercent,
        },
    )
    .unwrap();
    c.write_pcm(out, 0, &[0x69; 256]).unwrap();
    c.fill_capture(input, 0xa5).unwrap();
    c.start(input).unwrap();
    c.start(out).unwrap();
    (graph, out, input)
}

#[test]
fn realtek_pci_suspend_resume_owns_duplex_ram_and_requires_fresh_codec_routes() {
    let mut fixture = Fixture::new();
    let (model, mut function, state) = hardware();
    let mut c = claim(&mut function, &state, &mut fixture);
    let (old_graph, out, input) = routes(&mut c, &mut fixture);
    model.borrow_mut().dma_step_bytes = 128;
    advance(&model, 8);
    assert!(c.status(out).unwrap().period_completed);
    assert!(c.status(input).unwrap().period_completed);
    let retained = (
        c.corb.physical(),
        c.rirb.physical(),
        c.stream(out).unwrap().buffer.physical(),
        c.stream(input).unwrap().buffer.physical(),
    );
    c.suspend_pci_d3hot().unwrap();
    assert_eq!(state.borrow().words[0x54 / 4], 0x8003);
    assert_eq!(c.realtek_codecs.len(), 1);
    assert_eq!(c.routes.len(), 2);
    assert_eq!(
        c.streams[usize::from(out.descriptor_index())]
            .as_ref()
            .unwrap()
            .buffer
            .physical(),
        retained.2
    );
    assert_eq!(
        c.streams[usize::from(input.descriptor_index())]
            .as_ref()
            .unwrap()
            .buffer
            .physical(),
        retained.3
    );
    let before = access_counts(&model);
    assert!(c.start(out).is_err());
    assert!(c.poll_pin_sense(&old_graph, 4).is_err());
    assert_eq!(access_counts(&model), before);
    c.resume_pci_d0().unwrap();
    assert_eq!(
        (c.corb.physical(), c.rirb.physical()),
        (retained.0, retained.1)
    );
    assert!(c.realtek_codecs.is_empty() && c.routes.is_empty());
    assert!(c.start(out).is_err() && c.start(input).is_err());
    assert_eq!(
        c.initialize_realtek_codec(&old_graph),
        Err(Error::InvalidCodecGraph)
    );
    let (_, fresh_out, fresh_input) = routes(&mut c, &mut fixture);
    assert_ne!(fresh_out, out);
    assert_ne!(fresh_input, input);
    c.shutdown().unwrap();
}

#[test]
fn realtek_failed_stop_or_quiet_never_writes_pci_power_and_keeps_routes() {
    for failed_stop in [true, false] {
        let mut fixture = Fixture::new();
        let (model, mut function, state) = hardware();
        let mut c = claim(&mut function, &state, &mut fixture);
        let (_, out, _) = routes(&mut c, &mut fixture);
        let boundary = state.borrow().writes.len();
        let verbs = model.borrow().commands.len();
        if failed_stop {
            model.borrow_mut().stream_stop_stuck = true;
        } else {
            // Lose the actual EAPD-off ACK after the hardware effect.
            model.borrow_mut().drop_reply_command = Some(0x0147_0c00);
        }
        assert!(c.suspend_pci_d3hot().is_err());
        assert_eq!(state.borrow().writes.len(), boundary);
        assert_eq!(state.borrow().words[0x54 / 4] & 3, 0);
        assert_eq!(c.realtek_codecs.len(), 1);
        assert_eq!(c.routes.len(), 2);
        assert!(c.streams[usize::from(out.descriptor_index())].is_some());
        if failed_stop {
            assert_eq!(model.borrow().commands.len(), verbs);
        } else {
            assert_eq!(model.borrow().route_controls[&(0x14, 0xf0c)], 0);
            assert!(c.stopped);
        }
        {
            let mut m = model.borrow_mut();
            m.stream_stop_stuck = false;
            m.drop_reply_command = None;
        }
        c.reinitialize().unwrap();
        assert!(c.realtek_codecs.is_empty() && c.routes.is_empty());
    }
}

#[test]
fn realtek_failed_pci_power_and_resume_reset_keep_original_effect_reservations() {
    let mut fixture = Fixture::new();
    let (model, mut function, state) = hardware();
    let mut c = claim(&mut function, &state, &mut fixture);
    let (_, out, _) = routes(&mut c, &mut fixture);
    let pcm = c.stream(out).unwrap().buffer.physical();
    state.borrow_mut().reject_d3 = true;
    assert_eq!(
        c.suspend_pci_d3hot(),
        Err(pci::PowerError::Pci(pci::AttachError::PowerTransition))
    );
    assert_eq!(c.realtek_codecs.len(), 1);
    assert_eq!(c.routes.len(), 2);
    let before = access_counts(&model);
    assert!(c.start(out).is_err());
    assert_eq!(access_counts(&model), before);
    state.borrow_mut().reject_d3 = false;
    model.borrow_mut().reset_exit_stuck = true;
    assert!(c.resume_pci_d0().is_err());
    assert_eq!(c.realtek_codecs.len(), 1);
    assert_eq!(c.routes.len(), 2);
    assert_eq!(
        c.streams[usize::from(out.descriptor_index())]
            .as_ref()
            .unwrap()
            .buffer
            .physical(),
        pcm
    );
    let before = access_counts(&model);
    assert!(c.start(out).is_err());
    assert_eq!(access_counts(&model), before);
    model.borrow_mut().reset_exit_stuck = false;
    c.resume_pci_d0().unwrap();
    assert!(c.realtek_codecs.is_empty() && c.routes.is_empty());
    assert!(c.streams.iter().all(Option::is_none));
}

#[test]
fn cold_vendor_initialization_cannot_override_a_retained_raw_converter() {
    for vendor in [0x10ec_0882, 0x14f1_5045, 0x8384_7690, 0x1013_4213] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(vendor);
        let mut c = create(&model, &mut fixture, config()).unwrap();
        let graph = c.enumerate_codec(0).unwrap();
        let out = c
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        c.bind_converter(&graph, 2, out, 0).unwrap();
        let before = access_counts(&model);
        let error = match vendor >> 16 {
            0x10ec => c.initialize_realtek_codec(&graph).map(|_| ()),
            0x14f1 => c.initialize_conexant_codec(&graph).map(|_| ()),
            0x8384 => c.initialize_sigmatel_codec(&graph).map(|_| ()),
            _ => c.initialize_cirrus_codec(&graph).map(|_| ()),
        };
        assert_eq!(error, Err(Error::RouteInUse));
        assert_eq!(access_counts(&model), before);
        assert_eq!(c.converter_bindings.len(), 1);
        c.reinitialize().unwrap();
        assert!(c.converter_bindings.is_empty());
    }
}
