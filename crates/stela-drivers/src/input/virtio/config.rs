//! Bounded per-selector configuration reads on the input owner's transport.
use super::{DATA, Modern, SELECT, SIZE, SUBSELECT};

const CAPACITY: usize = 128;
const ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigSelector {
    pub select: u8,
    pub subselect: u8,
}

/// The readbacks and bytes from one attempt, including rejected attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigAttempt {
    pub generation_before: u8,
    pub generation_after: u8,
    pub selector_before: ConfigSelector,
    pub selector_after: ConfigSelector,
    pub reported_size: u8,
    bytes: [u8; CAPACITY],
    bytes_read: u8,
}
impl ConfigAttempt {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.bytes_read)]
    }
    fn coherent(&self, selector: ConfigSelector) -> bool {
        self.generation_before == self.generation_after
            && self.selector_before == selector
            && self.selector_after == selector
            && self.reported_size == self.bytes_read
    }
    const EMPTY: Self = Self {
        generation_before: 0,
        generation_after: 0,
        selector_before: ConfigSelector {
            select: 0,
            subselect: 0,
        },
        selector_after: ConfigSelector {
            select: 0,
            subselect: 0,
        },
        reported_size: 0,
        bytes: [0; CAPACITY],
        bytes_read: 0,
    };
}

/// At most three attempts; unused buffer entries are never observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigRead {
    requested: ConfigSelector,
    attempts: [ConfigAttempt; ATTEMPTS],
    count: u8,
}
impl ConfigRead {
    pub fn requested(&self) -> ConfigSelector {
        self.requested
    }
    pub fn attempts(&self) -> &[ConfigAttempt] {
        &self.attempts[..usize::from(self.count)]
    }
}

/// A coherent read of one selector only. KEY and SW may have different
/// generations; neither their union nor physical held state is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigSnapshot {
    evidence: ConfigRead,
}
impl ConfigSnapshot {
    pub fn evidence(&self) -> &ConfigRead {
        &self.evidence
    }
    pub fn bytes(&self) -> &[u8] {
        self.evidence.attempts().last().unwrap().bytes()
    }
}

/// Exhausted bounded attempts, preserving every size/readback and byte read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigSnapshotError {
    pub evidence: ConfigRead,
}

pub(super) enum CapabilityRead {
    Snapshot(ConfigSnapshot),
    Refused(Option<ConfigSnapshotError>),
}
impl CapabilityRead {
    pub(super) fn snapshot(&self) -> Option<&ConfigSnapshot> {
        match self {
            Self::Snapshot(snapshot) => Some(snapshot),
            Self::Refused(_) => None,
        }
    }
    pub(super) fn take_error(&mut self) -> Option<ConfigSnapshotError> {
        match self {
            Self::Snapshot(_) => None,
            Self::Refused(error) => error.take(),
        }
    }
}

// Private adapter: a test model can exercise the same read protocol, but cannot
// create a public source or attach a transport using these data-only objects.
trait Registers {
    fn write(&self, offset: usize, value: u8);
    fn read(&self, offset: usize) -> u8;
    fn generation(&self) -> u8;
}
impl Registers for Modern {
    fn write(&self, offset: usize, value: u8) {
        self.device.write8(offset, value);
    }
    fn read(&self, offset: usize) -> u8 {
        self.device.read8(offset)
    }
    fn generation(&self) -> u8 {
        self.config_generation()
    }
}

pub(super) fn capability(transport: &Modern, subselect: u8) -> CapabilityRead {
    read(
        transport,
        ConfigSelector {
            select: super::CONFIG_EVENTS,
            subselect,
        },
    )
}

fn read(registers: &impl Registers, requested: ConfigSelector) -> CapabilityRead {
    let mut evidence = ConfigRead {
        requested,
        attempts: [ConfigAttempt::EMPTY; ATTEMPTS],
        count: 0,
    };
    // Virtio 1.2 sections 2.5 and 5.8.5.1: select both fields, read the size,
    // and bracket this selector's data with config_generation. Never clamp an
    // oversized response into an apparently valid capability bitmap.
    // https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
    for index in 0..ATTEMPTS {
        registers.write(SELECT, requested.select);
        registers.write(SUBSELECT, requested.subselect);
        let mut attempt = ConfigAttempt {
            generation_before: registers.generation(),
            selector_before: ConfigSelector {
                select: registers.read(SELECT),
                subselect: registers.read(SUBSELECT),
            },
            reported_size: registers.read(SIZE),
            ..ConfigAttempt::EMPTY
        };
        if usize::from(attempt.reported_size) <= CAPACITY {
            for offset in 0..usize::from(attempt.reported_size) {
                attempt.bytes[offset] = registers.read(DATA + offset);
                attempt.bytes_read += 1;
            }
        }
        attempt.selector_after = ConfigSelector {
            select: registers.read(SELECT),
            subselect: registers.read(SUBSELECT),
        };
        attempt.generation_after = registers.generation();
        evidence.attempts[index] = attempt;
        evidence.count += 1;
        if attempt.coherent(requested) {
            return CapabilityRead::Snapshot(ConfigSnapshot { evidence });
        }
    }
    CapabilityRead::Refused(Some(ConfigSnapshotError { evidence }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::VecDeque, vec::Vec};
    use core::cell::RefCell;

    enum Access {
        Write(usize, u8),
        Read(usize, u8),
        Generation(u8),
    }
    struct Script(RefCell<VecDeque<Access>>);
    impl Registers for Script {
        fn write(&self, offset: usize, value: u8) {
            assert!(
                matches!(self.0.borrow_mut().pop_front(), Some(Access::Write(o, v)) if (o, v) == (offset, value))
            );
        }
        fn read(&self, offset: usize) -> u8 {
            let Some(Access::Read(expected, value)) = self.0.borrow_mut().pop_front() else {
                panic!("unexpected configuration read at {offset}")
            };
            assert_eq!(offset, expected);
            value
        }
        fn generation(&self) -> u8 {
            let Some(Access::Generation(value)) = self.0.borrow_mut().pop_front() else {
                panic!("unexpected generation read")
            };
            value
        }
    }
    fn selector() -> ConfigSelector {
        ConfigSelector {
            select: 0x11,
            subselect: 1,
        }
    }
    fn attempt(
        script: &mut VecDeque<Access>,
        requested: ConfigSelector,
        generations: (u8, u8),
        selectors: (ConfigSelector, ConfigSelector),
        size: u8,
        bytes: &[u8],
    ) {
        script.extend([
            Access::Write(SELECT, requested.select),
            Access::Write(SUBSELECT, requested.subselect),
            Access::Generation(generations.0),
            Access::Read(SELECT, selectors.0.select),
            Access::Read(SUBSELECT, selectors.0.subselect),
            Access::Read(SIZE, size),
        ]);
        script.extend(
            bytes
                .iter()
                .enumerate()
                .map(|(i, &b)| Access::Read(DATA + i, b)),
        );
        script.extend([
            Access::Read(SELECT, selectors.1.select),
            Access::Read(SUBSELECT, selectors.1.subselect),
            Access::Generation(generations.1),
        ]);
    }

    #[test]
    fn retry_retains_rejected_bytes_and_accepts_only_the_stable_attempt() {
        let selected = selector();
        let mut script = VecDeque::new();
        attempt(
            &mut script,
            selected,
            (255, 0),
            (selected, selected),
            2,
            &[0xff, 0xaa],
        );
        attempt(&mut script, selected, (0, 0), (selected, selected), 1, &[8]);
        let script = Script(RefCell::new(script));
        let CapabilityRead::Snapshot(snapshot) = read(&script, selected) else {
            panic!("stable retry refused")
        };
        assert!(script.0.borrow().is_empty());
        assert_eq!(snapshot.bytes(), &[8]);
        let history = snapshot.evidence().attempts();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].bytes(), &[0xff, 0xaa]);
        assert_eq!(
            (history[0].generation_before, history[0].generation_after),
            (255, 0)
        );
        assert_eq!(snapshot.evidence().requested(), selected);
    }

    #[test]
    fn oversized_and_mismatched_selectors_exhaust_without_clamping_or_empty_success() {
        let selected = selector();
        let other = ConfigSelector {
            select: 0x11,
            subselect: 5,
        };
        let mut script = VecDeque::new();
        attempt(
            &mut script,
            selected,
            (3, 3),
            (selected, selected),
            129,
            &[],
        );
        attempt(&mut script, selected, (3, 3), (other, selected), 1, &[0xff]);
        attempt(&mut script, selected, (3, 3), (selected, other), 1, &[0xaa]);
        let script = Script(RefCell::new(script));
        let CapabilityRead::Refused(Some(error)) = read(&script, selected) else {
            panic!("invalid capability was accepted")
        };
        assert!(script.0.borrow().is_empty(), "exactly three attempts");
        let history = error.evidence.attempts();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].reported_size, 129);
        assert!(history[0].bytes().is_empty(), "no oversized data read");
        assert_eq!(history[1].selector_before, other);
        assert_eq!(history[1].bytes(), &[0xff]);
        assert_eq!(history[2].selector_after, other);
        assert_eq!(history[2].bytes(), &[0xaa]);
    }

    #[test]
    fn full_bitmap_and_empty_response_preserve_their_exact_sizes() {
        let selected = selector();
        for bytes in [Vec::new(), (0..128u8).collect::<Vec<_>>()] {
            let mut script = VecDeque::new();
            attempt(
                &mut script,
                selected,
                (7, 7),
                (selected, selected),
                bytes.len() as u8,
                &bytes,
            );
            let script = Script(RefCell::new(script));
            let CapabilityRead::Snapshot(snapshot) = read(&script, selected) else {
                panic!("valid exact size refused")
            };
            assert_eq!(snapshot.bytes(), bytes);
            assert_eq!(snapshot.evidence().attempts().len(), 1);
            assert!(script.0.borrow().is_empty());
        }
    }

    fn capability_read(subselect: u8, generation: u8, valid: bool) -> CapabilityRead {
        let selected = ConfigSelector {
            select: 0x11,
            subselect,
        };
        let mut script = VecDeque::new();
        for _ in 0..if valid { 1 } else { ATTEMPTS } {
            attempt(
                &mut script,
                selected,
                (generation, generation),
                (selected, selected),
                if valid { 1 } else { 255 },
                if valid { &[8] } else { &[] },
            );
        }
        let script = Script(RefCell::new(script));
        let read = read(&script, selected);
        assert!(script.0.borrow().is_empty());
        read
    }

    #[test]
    fn independent_generations_keep_evidence_and_never_supply_held_state() {
        use super::super::{Format, InitialState, observation_tests::model};
        model(|input| {
            input.observation = None;
            input.capability_reads = [capability_read(1, 7, true), capability_read(5, 9, true)];
            input.install_observation();
            let source = input.observation_sources().pop().unwrap();
            let Format::Linux { capabilities } = &source.description().format else {
                panic!("missing verified capability bitmaps")
            };
            assert_eq!(capabilities.keys, [3]);
            assert_eq!(capabilities.switches, [3]);
            assert_eq!(source.initial_state(), InitialState::unknown());
            let [keys, switches] = input.capability_snapshots().unwrap();
            assert_eq!(keys.evidence().attempts()[0].generation_after, 7);
            assert_eq!(switches.evidence().attempts()[0].generation_after, 9);
            assert_eq!(keys.evidence().requested().subselect, 1);
            assert_eq!(switches.evidence().requested().subselect, 5);
        });
    }

    #[test]
    fn either_refused_bitmap_disables_source_but_guest_poll_and_once_only_errors_continue() {
        use super::super::{
            Event, Input, PollError,
            observation_tests::{complete, model},
        };
        for valid in [[false, true], [true, false], [false, false]] {
            model(|input| {
                input.observation = None;
                input.capability_reads = [
                    capability_read(1, 7, valid[0]),
                    capability_read(5, 9, valid[1]),
                ];
                input.install_observation();
                assert!(input.observation_sources().is_empty());
                assert!(input.capability_snapshots().is_none());
                complete(
                    input,
                    &[Event {
                        kind: 1,
                        code: 30,
                        value: 1,
                    }],
                );
                let polled = input.poll_observed();
                assert_eq!(
                    polled.inputs,
                    [Input::Key {
                        usage: 4,
                        pressed: true
                    }]
                );
                assert!(polled.observations.items.is_empty());
                let errors: Vec<_> = polled
                    .first_error
                    .into_iter()
                    .chain(polled.later_errors)
                    .collect();
                let expected: Vec<_> = [1, 5]
                    .into_iter()
                    .zip(valid)
                    .filter_map(|(kind, valid)| (!valid).then_some(kind))
                    .collect();
                assert_eq!(errors.len(), expected.len());
                for (error, expected) in errors.into_iter().zip(expected) {
                    let PollError::ConfigSnapshot(error) = error else {
                        panic!("wrong cause")
                    };
                    assert_eq!(error.evidence.requested().subselect, expected);
                    assert_eq!(error.evidence.attempts().len(), ATTEMPTS);
                    assert_eq!(error.evidence.attempts()[0].reported_size, 255);
                }
                let next = input.poll_observed();
                assert!(next.first_error.is_none());
                assert!(next.later_errors.is_empty());
                assert!(next.inputs.is_empty());
                assert!(next.observations.items.is_empty());
                assert!(input.observation_sources().is_empty());
            });
        }
    }
}
