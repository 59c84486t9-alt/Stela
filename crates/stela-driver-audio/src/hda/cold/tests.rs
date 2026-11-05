// SPDX-License-Identifier: GPL-2.0-only
//! Hostile inherited-controller models; no platform/hardware completion claim.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone)]
struct Clock(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 1);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    Read(usize, u8),
    Write(usize, u8, u32),
}
struct State {
    values: BTreeMap<usize, u32>,
    effects: Vec<Effect>,
    blocked: Option<usize>,
    fail_read: Option<usize>,
    inherited: Vec<u8>,
}
struct Model(Rc<RefCell<State>>);
impl Model {
    fn read(&mut self, offset: usize, width: u8) -> u32 {
        let mut s = self.0.borrow_mut();
        s.effects.push(Effect::Read(offset, width));
        if s.fail_read == Some(offset) {
            return u32::MAX;
        }
        *s.values.get(&offset).unwrap_or(&0)
    }
    fn write(&mut self, offset: usize, width: u8, value: u32) {
        let mut s = self.0.borrow_mut();
        s.effects.push(Effect::Write(offset, width, value));
        if s.blocked == Some(offset) {
            return;
        }
        if offset == CORBSTS
            || offset == RIRBSTS
            || (offset >= 0x80 && (offset - 0x80) % 0x20 == SD_STS)
        {
            let previous = *s.values.get(&offset).unwrap_or(&0);
            s.values.insert(offset, previous & !value);
        } else {
            s.values.insert(offset, value);
        }
    }
}
impl Registers for Model {
    fn read8(&mut self, o: usize) -> u8 {
        self.read(o, 1) as u8
    }
    fn read16(&mut self, o: usize) -> u16 {
        self.read(o, 2) as u16
    }
    fn read32(&mut self, o: usize) -> u32 {
        self.read(o, 4)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.write(o, 1, u32::from(v));
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.write(o, 2, u32::from(v));
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.write(o, 4, v);
    }
}
fn fixture() -> (Model, Clock, Rc<RefCell<State>>) {
    let mut values = BTreeMap::new();
    for (o, v) in [
        (VMAJ, 1),
        (VMIN, 0),
        (GCAP, (3 << 8) | (3 << 12) | (2 << 3) | 1),
        (INTCTL, u32::MAX),
        (WAKEEN, 0x7fff),
        (GCTL, GCTL_RESET | GCTL_UNSOL),
        (CORBCTL, 3),
        (RIRBCTL, 7),
        (CORBSTS, 1),
        (RIRBSTS, 5),
        (DPLBASE, 0x12340001),
        (DPUBASE, 0x89abcdef),
    ] {
        values.insert(o, v);
    }
    for i in 0..8 {
        values.insert(stream_base(i) + SD_CTL, 0x1e);
        values.insert(stream_base(i) + SD_STS, u32::from(SD_STATUS));
        values.insert(
            stream_base(i) + SD_BDLPL,
            0xa0000000 + u32::from(i) * 0x1000,
        );
    }
    let state = Rc::new(RefCell::new(State {
        values,
        effects: Vec::new(),
        blocked: None,
        fail_read: None,
        inherited: (0..=255).cycle().take(8192).collect(),
    }));
    (Model(state.clone()), Clock(Rc::new(Cell::new(0))), state)
}
fn config() -> Config {
    Config {
        transition_timeout_us: 8,
        ..Config::default()
    }
}

#[test]
fn cold_stop_covers_every_inherited_descriptor_and_position_command_dma_without_new_memory() {
    let (mut model, clock, state) = fixture();
    let original = state.borrow().inherited.clone();
    let stopped = stop_inherited(&mut model, &clock, &config()).unwrap();
    assert_eq!(stopped.streams(), 8);
    let s = state.borrow();
    assert_eq!(s.inherited, original);
    for i in 0..8 {
        let ctl = stream_base(i) + SD_CTL;
        assert_eq!(s.values[&ctl] & u32::from(SD_RUN | SD_STATUS), 0);
        assert!(s.effects.contains(&Effect::Write(ctl, 1, 0)));
        assert_eq!(
            s.values[&(stream_base(i) + SD_BDLPL)],
            0xa0000000 + u32::from(i) * 0x1000
        );
    }
    for o in [INTCTL, WAKEEN, CORBCTL, RIRBCTL, DPLBASE, DPUBASE] {
        assert_eq!(s.values[&o], 0);
    }
    assert_eq!(s.values[&GCTL], GCTL_RESET);
    assert!(!s.effects.iter().any(|e| matches!(e,Effect::Write(o,_,_) if
        [CORBLBASE,CORBUBASE,RIRBLBASE,RIRBUBASE].contains(o))));
    assert!(
        !s.effects
            .iter()
            .any(|e| matches!(e,Effect::Write(GCTL,_,v) if v&GCTL_RESET==0))
    );
}

#[test]
fn cold_stop_refuses_every_missing_engine_interrupt_position_ack_and_failed_read() {
    let offsets = [
        INTCTL,
        WAKEEN,
        GCTL,
        CORBCTL,
        RIRBCTL,
        DPLBASE,
        DPUBASE,
        stream_base(0) + SD_CTL,
        stream_base(7) + SD_CTL,
        CORBSTS,
        RIRBSTS,
    ];
    let offsets = offsets
        .into_iter()
        .chain((0..8).flat_map(|index| [stream_base(index) + SD_CTL, stream_base(index) + SD_STS]));
    for o in offsets {
        for read in [false, true] {
            let (mut model, clock, state) = fixture();
            if read {
                state.borrow_mut().fail_read = Some(o);
            } else {
                state.borrow_mut().blocked = Some(o);
            }
            assert!(
                stop_inherited(&mut model, &clock, &config()).is_err(),
                "offset {o:x}, failed read {read}"
            );
            assert_eq!(state.borrow().inherited.len(), 8192);
        }
    }
}

#[test]
fn cold_stop_checks_gcapped_topology_before_mutation_and_never_accepts_unavailable_version() {
    for (offset, value) in [
        (GCAP, 0),
        (GCAP, u32::from(u16::MAX)),
        (VMAJ, 255),
        (VMIN, 255),
    ] {
        let (mut model, clock, state) = fixture();
        state.borrow_mut().values.insert(offset, value);
        assert!(stop_inherited(&mut model, &clock, &config()).is_err());
        assert!(
            !state
                .borrow()
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Write(..)))
        );
    }
}

#[test]
fn cold_stop_supports_the_last_physical_bidirectional_descriptor_without_allocated_streams() {
    let (mut model, clock, state) = fixture();
    state
        .borrow_mut()
        .values
        .insert(GCAP, (10 << 8) | (10 << 12) | (10 << 3) | 1);
    for i in 8..30 {
        state
            .borrow_mut()
            .values
            .insert(stream_base(i) + SD_CTL, 0x1e);
        state
            .borrow_mut()
            .values
            .insert(stream_base(i) + SD_STS, u32::from(SD_STATUS));
    }
    assert_eq!(
        stop_inherited(&mut model, &clock, &config())
            .unwrap()
            .streams(),
        30
    );
    assert!(
        state
            .borrow()
            .effects
            .contains(&Effect::Write(stream_base(29) + SD_CTL, 1, 0))
    );
}

// SAFETY: private synchronous peripheral peer consumes model microseconds.
unsafe impl crate::bus::pci::power::Timer for Clock {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.0.set(
            self.0
                .get()
                .checked_add(us)
                .expect("bounded virtual minimum"),
        );
        Ok(())
    }
}
