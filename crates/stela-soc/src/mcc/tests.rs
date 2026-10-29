use super::*;
use stela_contracts::interrupt::InterruptLatch;
fn lifecycle() -> LifecycleState {
    LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    }
}
fn owner() -> Controller {
    Controller::initialized(
        Configuration {
            dram: alloc::vec![[0xffff0000; 4]; 4],
            weights: [1; 32],
        },
        lifecycle(),
    )
    .unwrap()
}
#[test]
fn source_apertures_channels_and_declared_initialization_are_owned_together() {
    let owner = owner();
    assert_eq!(owner.origin(), Origin::StelaInitialized);
    let mut latch = InterruptLatch::new();
    for aperture in 0..4 {
        let mut view = owner.view(aperture).unwrap();
        let mut access = Access::new(0, 0, &mut latch);
        for channel in 0..CHANNELS {
            assert_eq!(
                view.read(
                    DCS_BASE + u64::from(channel) * DCS_STRIDE + DRAM_CONFIG,
                    Width::Word,
                    &mut access
                ),
                Ok(0xffff0000)
            );
        }
        for plane in 0..PLANES {
            assert_eq!(
                view.read(
                    u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                    Width::Word,
                    &mut access
                ),
                Ok(0)
            );
        }
        assert_eq!(
            view.read(GROUP_QUOTA + 31 * 4, Width::Word, &mut access),
            Ok(1 << 16)
        );
        assert!(
            view.read(GROUP_QUOTA + 32 * 4, Width::Word, &mut access)
                .is_err()
        );
    }
    assert!(owner.view(4).is_err());
    assert!(owner.requests().is_empty());
}
#[test]
fn requested_ways_never_become_status_and_broadcast_preserves_other_apertures() {
    let owner = owner();
    let mut view = owner.view(1).unwrap();
    let mut alias = owner.view(1).unwrap();
    let mut other = owner.view(2).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 123, &mut latch);
    view.write(BROADCAST, Width::Word, 1, &mut access).unwrap();
    view.write(CACHE_COMMAND, Width::Word, 12, &mut access)
        .unwrap();
    for plane in 0..PLANES {
        assert!(
            alias
                .read(
                    u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                    Width::Word,
                    &mut access
                )
                .is_err()
        );
        assert_eq!(
            other.read(
                u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                Width::Word,
                &mut access
            ),
            Ok(0)
        );
    }
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].kind,
        RequestKind::Ways {
            plane: 0,
            ways: 12,
            broadcast: true
        }
    );
    assert_eq!(requests[0].at, 123);
    assert!(alias.read(CACHE_COMMAND, Width::Word, &mut access).is_err());
    assert!(
        view.write(CACHE_COMMAND, Width::Word, 13, &mut access)
            .is_err()
    );
    assert_eq!(owner.requests(), requests);
}
#[test]
fn native_observations_remain_observations_and_requests_do_not_settle_quota() {
    let initial = owner();
    let mut observations = initial.observations();
    let status = observations
        .iter_mut()
        .find(|o| o.aperture == 0 && o.offset == CACHE_STATUS)
        .unwrap();
    status.value = (12 << 9) | (12 << 4);
    observations
        .iter_mut()
        .find(|o| o.aperture == 0 && o.offset == GROUP_QUOTA)
        .unwrap()
        .value |= 1 << 31;
    let mut unknown = observations.clone();
    unknown
        .iter_mut()
        .find(|o| o.aperture == 0 && o.offset == CACHE_STATUS)
        .unwrap()
        .known = !CACHE_COUNTS & u64::from(u32::MAX);
    let captured = Controller::from_observations(4, lifecycle(), &unknown).unwrap();
    assert_eq!(captured.origin(), Origin::RetainedObservation);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        captured
            .view(0)
            .unwrap()
            .read(CACHE_STATUS, Width::Word, &mut access)
            .is_err()
    );
    let captured = Controller::from_observations(4, lifecycle(), &observations).unwrap();
    let mut view = captured.view(0).unwrap();
    assert_eq!(
        view.read(CACHE_STATUS, Width::Word, &mut access),
        Ok((12 << 9) | (12 << 4))
    );
    view.write(
        GROUP_QUOTA,
        Width::Word,
        48 | (3 << 16) | (1 << 24) | (1 << 31),
        &mut access,
    )
    .unwrap();
    assert!(view.read(GROUP_QUOTA, Width::Word, &mut access).is_err());
    let retained = captured
        .observations()
        .into_iter()
        .find(|o| o.aperture == 0 && o.offset == GROUP_QUOTA)
        .unwrap();
    assert_eq!(retained.value & (1 << 31), 1 << 31);
    assert_eq!(retained.known, u64::from(u32::MAX) & !0x017f_003f);
    assert_eq!(
        captured.requests()[0].kind,
        RequestKind::Quota {
            group: 0,
            units: 48,
            weight: 3,
            attribute: true,
            broadcast: false
        }
    );
    assert!(
        view.write(GROUP_QUOTA, Width::Word, 49, &mut access)
            .is_err()
    );
    assert!(
        view.write(
            GROUP_QUOTA,
            Width::Word,
            48 | (3 << 16) | (1 << 24),
            &mut access,
        )
        .is_err()
    );
    assert_eq!(captured.requests().len(), 1);
}
#[test]
fn drain_temperature_counter_clear_and_accounting_never_succeed_without_backend() {
    let owner = owner();
    let mut view = owner.view(0).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for offset in [
        DCS_BASE + 0x41c,
        DCS_BASE + 0x4000,
        DCS_BASE + 0xec8,
        DCS_BASE + 0xed0,
        0xc000,
        0x159000,
        0x25000,
    ] {
        assert!(view.read(offset, Width::Word, &mut access).is_err());
        assert!(view.read(offset, Width::Double, &mut access).is_err());
    }
    for offset in [
        DCS_BASE + DCS_DRAIN,
        DCS_BASE + 0x580,
        DCS_BASE + 0x584,
        DCS_BASE + 0x588,
    ] {
        assert!(view.write(offset, Width::Word, 0, &mut access).is_err());
    }
    assert!(
        view.write(
            CACHE_STATUS,
            Width::Word,
            (12 << 9) | (12 << 4),
            &mut access
        )
        .is_err()
    );
    assert!(owner.requests().is_empty());
    assert!(
        view.read(DCS_BASE + DCS_DRAIN, Width::Word, &mut access)
            .is_err()
    );
}
#[test]
fn shared_lifecycle_preserves_exact_requests_and_refuses_native_reset_loss() {
    let owner = owner();
    let mut first = owner.view(0).unwrap();
    let mut last = owner.view(3).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 77, &mut latch);
    first
        .write(SHARED_GATING, Width::Word, 1 << 28, &mut access)
        .unwrap();
    last.write(
        DCS_BASE + 3 * DCS_STRIDE + DCS_GATING,
        Width::Word,
        0x1100,
        &mut access,
    )
    .unwrap();
    let expected = owner.requests();
    let paused = LifecycleState {
        clocked: false,
        ..lifecycle()
    };
    Lifecycle::set_lifecycle(&mut first, paused, &mut access);
    assert_eq!(owner.lifecycle_state(), paused);
    assert!(
        last.read(DCS_BASE + DRAM_CONFIG, Width::Word, &mut access)
            .is_err()
    );
    assert!(
        first
            .write(SHARED_GATING, Width::Word, 0, &mut access)
            .is_err()
    );
    assert_eq!(owner.requests(), expected);
    assert!(
        Lifecycle::check_lifecycle(
            &last,
            LifecycleState {
                reset: true,
                ..lifecycle()
            }
        )
        .is_err()
    );
    assert!(
        Lifecycle::check_lifecycle(
            &last,
            LifecycleState {
                powered: false,
                retention: false,
                ..lifecycle()
            }
        )
        .is_err()
    );
    Lifecycle::set_lifecycle(&mut last, lifecycle(), &mut access);
    assert_eq!(owner.requests(), expected);
    assert!(first.read(SHARED_GATING, Width::Word, &mut access).is_err());
    assert_eq!(
        expected.iter().map(|r| r.serial).collect::<Vec<_>>(),
        [1, 2]
    );
}
#[test]
fn malformed_geometry_observations_and_accesses_have_no_partial_effects() {
    for count in [0, 17] {
        assert!(
            Controller::initialized(
                Configuration {
                    dram: alloc::vec![[0;4];count],
                    weights: [1; 32]
                },
                lifecycle()
            )
            .is_err()
        );
    }
    assert!(
        Controller::initialized(
            Configuration {
                dram: alloc::vec![[0;4];4],
                weights: [0; 32]
            },
            lifecycle()
        )
        .is_err()
    );
    let owner = owner();
    let source = owner.observations();
    let mut bad = source.clone();
    bad.pop();
    assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
    let mut bad = source.clone();
    bad.push(source[0]);
    assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
    let mut bad = source.clone();
    bad[0].value = 1 << 32;
    assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
    let mut bad = source;
    bad[0].aperture = 4;
    assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
    let mut view = owner.view(0).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for (offset, width) in [
        (CACHE_COMMAND + 1, Width::Word),
        (CACHE_COMMAND, Width::Double),
        (APERTURE_BYTES, Width::Word),
        (BROADCAST, Width::Half),
    ] {
        assert!(view.read(offset, width, &mut access).is_err());
        assert!(view.write(offset, width, 0, &mut access).is_err());
    }
    assert!(view.write(BROADCAST, Width::Word, 2, &mut access).is_err());
    assert!(owner.requests().is_empty());
    assert_eq!(view.read(BROADCAST, Width::Word, &mut access), Ok(0));
}
