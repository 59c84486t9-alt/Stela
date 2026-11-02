use super::*;
extern crate std;
use crate::bus::pci::{ConfigError, ConfigFailure};
use alloc::sync::Arc;

// Actual current PCI errors are already multiword failure/effect metadata.
// No future controller SDK or hardware producer is needed by this generic test.
type Cause = ConfigError;
fn config() -> Cause {
    ConfigError::write_may_have_applied(
        0x54,
        4,
        ConfigFailure::Readback {
            offset: 0x54,
            width: 4,
            expected: 0xfee0_0010,
            observed: 0xffff_ffff,
        },
    )
}
fn other_config(index: usize) -> Cause {
    let offset = u16::try_from(0x10 + 4 * index).expect("bounded fixture offset");
    ConfigError::write_may_have_applied(
        offset,
        4,
        ConfigFailure::Readback {
            offset,
            width: 4,
            expected: 0x8765_4321,
            observed: 0xdead_cafe,
        },
    )
}
#[test]
fn actual_multiword_config_causes_keep_readback_width_offset_and_write_effect() {
    for expected in [config(), other_config(0)] {
        let cell = FirstFault::new();
        assert_eq!(cell.observe(), FaultState::Empty);
        assert!(cell.latch(expected));
        assert!(!cell.latch(other_config(1)));
        assert_eq!(cell.observe(), FaultState::Ready(expected));
    }
}
#[test]
fn interrupted_writer_stays_closed_without_reading_uninitialized_payload() {
    let cell = FirstFault::<Cause>::new();
    assert!(testing::claim(&cell));
    // Interruption is deliberately outside production latch's indivisible code
    // prefix; the control simulates an owner lost immediately after its CAS.
    let interruption = std::panic::catch_unwind(|| panic!("simulated interrupted writer"));
    assert!(interruption.is_err());
    for _ in 0..4 {
        assert_eq!(cell.observe(), FaultState::Publishing);
        assert!(!cell.latch(other_config(2)));
    }
    // No finish/reset is performed: this exact cell remains closed forever.
}
#[test]
fn nested_publications_keep_observation_separate_from_each_original_cause() {
    let outer = FirstFault::<Cause>::new();
    let inner = FirstFault::<Cause>::new();
    assert!(testing::claim(&outer));
    let observed = outer.observe();
    assert_eq!(observed, FaultState::Publishing);
    // Observation has a different type: no Cause is manufactured from it.
    assert!(inner.latch(other_config(3)));
    assert_eq!(inner.observe(), FaultState::Ready(other_config(3)));
    assert_eq!(outer.observe(), FaultState::Publishing);
    // SAFETY: this fixture owns outer's sole successful simulated claim; no
    // nested reader or inner publisher can access/finish its payload.
    unsafe { testing::finish(&outer, config()) };
    assert_eq!(outer.observe(), FaultState::Ready(config()));
    assert_eq!(inner.observe(), FaultState::Ready(other_config(3)));
}
#[test]
fn concurrent_writers_publish_exactly_one_complete_original_payload() {
    let cell = Arc::new(FirstFault::<Cause>::new());
    let start = Arc::new(std::sync::Barrier::new(9));
    let mut threads = alloc::vec::Vec::new();
    for index in 0..8 {
        let cell = cell.clone();
        let start = start.clone();
        threads.push(std::thread::spawn(move || {
            let candidate = other_config(index);
            start.wait();
            (candidate, cell.latch(candidate))
        }));
    }
    start.wait();
    let mut winner = None;
    for thread in threads {
        let (candidate, published) = thread.join().unwrap();
        if published {
            assert!(winner.replace(candidate).is_none());
        }
    }
    let winner = winner.expect("one writer must claim the initial cell");
    assert_eq!(cell.observe(), FaultState::Ready(winner));
    assert!(!cell.latch(config()));
    assert_eq!(cell.observe(), FaultState::Ready(winner));
}
