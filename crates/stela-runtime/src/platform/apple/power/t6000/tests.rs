use super::*;
use alloc::{boxed::Box, vec};
use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

const LIVE: LifecycleState = LifecycleState {
    powered: true,
    clocked: true,
    quiesced: false,
    reset: false,
    retention: true,
};
const FULL: Instance = Instance {
    complexes: 0x3f,
    cio_ports: 0xf,
    cpm_controls: 7,
    isp_clocks: 0xf,
};
fn words(geometry: &[Instance], value: u32) -> Vec<Observation> {
    geometry
        .iter()
        .enumerate()
        .flat_map(|(instance, layout)| {
            [Bank::Pmgr, Bank::ClkGenSoc]
                .into_iter()
                .flat_map(move |bank| {
                    layout
                        .offsets(bank)
                        .into_iter()
                        .map(move |offset| Observation {
                            instance: instance as u8,
                            bank,
                            offset,
                            value,
                            known: u32::MAX,
                        })
                })
        })
        .collect()
}
fn controller(geometry: &[Instance], value: u32) -> Controller {
    Controller::from_observations(geometry.to_vec(), LIVE, words(geometry, value)).unwrap()
}
#[test]
fn all_source_selectors_and_cio_ports_keep_ordered_mounted_inputs() {
    let owner = controller(&[FULL], 0x8000);
    let mut bus = Bus::new();
    let id = bus.add(Box::new(owner.view(0).unwrap()));
    let base = 0x28e080000;
    bus.map(id, base, 0x80000, 0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 11, &mut pins);
    for selector in 0..6 {
        let offset = GPCE_BASE + selector * 4;
        assert_eq!(
            bus.read(base + offset, Width::Word, &mut access),
            Ok(0x8000)
        );
        bus.write(base + offset, Width::Word, 0x800f, &mut access)
            .unwrap();
        assert!(bus.read(base + offset, Width::Word, &mut access).is_err());
    }
    for port in 0..4 {
        bus.write(base + CIO, Width::Word, 1 << port, &mut access)
            .unwrap();
    }
    let requests = owner.requests();
    assert_eq!(requests.len(), 10);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.serial, index as u64 + 1);
        assert_eq!(request.instance, 0);
        if index < 6 {
            assert_eq!(
                request.kind,
                RequestKind::Complex {
                    selector: index as u8,
                    target: 15
                }
            );
        } else {
            assert_eq!(
                request.kind,
                RequestKind::Cio {
                    port: index as u8 - 6
                }
            );
        }
    }
    assert!(bus.read(base + CIO, Width::Word, &mut access).is_err());
    assert!(bus.advance(&mut access).is_err());
    assert_eq!(owner.requests(), requests);
    // No made-up target/current status, PC, IRQ or retirement is generated.
    assert!(pins.take_aic_inputs().is_empty());
}
#[test]
fn supplied_board_geometry_does_not_admit_maximum_source_capacity() {
    let layout = Instance {
        complexes: 7,
        cio_ports: 5,
        cpm_controls: 7,
        isp_clocks: 0xf,
    };
    let owner = controller(&[layout], 0);
    let mut view = owner.view(0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut pins);
    assert!(owner.view(1).is_err());
    assert!(
        view.write(GPCE_BASE + 12, Width::Word, 15, &mut access)
            .is_err()
    );
    assert!(view.write(CIO, Width::Word, 2, &mut access).is_err());
    assert!(view.write(CIO, Width::Word, 3, &mut access).is_err());
    assert!(view.write(CIO, Width::Word, 0, &mut access).is_err());
    assert!(
        view.write(GPCE_BASE, Width::Double, 15, &mut access)
            .is_err()
    );
    assert!(view.write(0x4000, Width::Word, 1, &mut access).is_err());
    assert!(owner.requests().is_empty());
    view.write(CIO, Width::Word, 4, &mut access).unwrap();
}
#[test]
fn unknown_or_busy_capture_cannot_become_idle_or_a_healthy_zero() {
    let mut observations = words(&[FULL], 0);
    observations[0].known = 0;
    observations[1].value = GPCE_BUSY;
    let owner = Controller::from_observations(vec![FULL], LIVE, observations).unwrap();
    assert_eq!(owner.captured_pending().len(), 2);
    let mut view = owner.view(0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut pins);
    assert!(view.read(GPCE_BASE, Width::Word, &mut access).is_err());
    assert!(view.write(GPCE_BASE, Width::Word, 15, &mut access).is_err());
    assert_eq!(
        view.read(GPCE_BASE + 4, Width::Word, &mut access),
        Ok(u64::from(GPCE_BUSY))
    );
    assert!(view.advance(&mut access).is_err());
    assert!(owner.requests().is_empty());
    assert_eq!(owner.captured_pending().len(), 2);
}
#[test]
fn shared_views_keep_partial_prefix_and_knownness_across_independent_pauses() {
    let owner = controller(&[FULL, FULL], 0);
    let mut a = owner.view(0).unwrap();
    let mut b = owner.view(1).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 20, &mut pins);
    a.write(GPCE_BASE, Width::Word, 15, &mut access).unwrap();
    b.write(CIO, Width::Word, 8, &mut access).unwrap();
    let prefix = owner.requests();
    let observation = owner.observations();
    let prior = owner.captured_pending();
    for paused in [
        LifecycleState {
            clocked: false,
            ..LIVE
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..LIVE
        },
        LifecycleState {
            quiesced: true,
            ..LIVE
        },
    ] {
        a.check_lifecycle(paused).unwrap();
        a.set_lifecycle(paused, &mut access);
        assert_eq!(b.advance(&mut access), Ok(None));
        if !paused.powered || !paused.clocked {
            assert!(b.read(CPM_BASE, Width::Word, &mut access).is_err());
        } else {
            // DMA/execution quiesce does not gate the AP configuration bus.
            assert_eq!(b.read(CPM_BASE, Width::Word, &mut access), Ok(0));
        }
        assert_eq!(owner.requests(), prefix);
        assert_eq!(owner.observations(), observation);
        assert_eq!(owner.captured_pending(), prior);
        b.set_lifecycle(LIVE, &mut access);
        assert!(a.advance(&mut access).is_err());
    }
    for destructive in [
        LifecycleState {
            reset: true,
            ..LIVE
        },
        LifecycleState {
            powered: false,
            retention: false,
            ..LIVE
        },
    ] {
        assert!(b.check_lifecycle(destructive).is_err());
        assert_eq!(owner.lifecycle(), LIVE);
        assert_eq!(owner.requests(), prefix);
    }
}
#[test]
fn nonrequest_fields_and_unknown_native_status_cannot_be_software_cleared() {
    let owner = controller(&[FULL], 0x8000);
    let mut view = owner.view(0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut pins);
    assert!(view.write(GPCE_BASE, Width::Word, 15, &mut access).is_err());
    assert!(
        view.write(GPCE_BASE, Width::Word, 0x8001, &mut access)
            .is_err()
    );
    view.write(GPCE_BASE, Width::Word, 0x802f, &mut access)
        .unwrap();
    let prefix = owner.requests();
    assert_eq!(prefix[0].written, 0x802f);
    assert!(
        view.write(GPCE_BASE, Width::Word, 0x8000, &mut access)
            .is_err()
    );
    assert!(view.read(GPCE_BASE, Width::Word, &mut access).is_err());
    assert_eq!(owner.requests(), prefix);
}
#[test]
fn gating_configuration_preserves_captured_fields_and_does_not_invent_idle_edges() {
    let owner = controller(&[FULL], 0x1234);
    let mut view = owner.view(0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut pins);
    for offset in [CPM_BASE, CPM_BASE + 8, CPM_BASE + 16] {
        view.write(offset, Width::Word, 0x80001234, &mut access)
            .unwrap();
        assert_eq!(view.read(offset, Width::Word, &mut access), Ok(0x80001234));
        assert!(view.write(offset, Width::Word, 0, &mut access).is_err());
        view.write(offset, Width::Word, 0x1234, &mut access)
            .unwrap();
    }
    assert_eq!(owner.requests().len(), 6);
    // GPCE phase/status and the nonzero CIO request bit are captured
    // unresolved work, not a new idle queue.
    assert!(view.advance(&mut access).is_err());
    assert_eq!(owner.captured_pending().len(), 7);
}
#[test]
fn mounted_isp_reference_clock_requests_share_order_and_kept_busy_ownership() {
    let owner = controller(&[FULL], 0x4000);
    let mut bus = Bus::new();
    let clock = bus.add(Box::new(owner.clock_view(0).unwrap()));
    let pmgr = bus.add(Box::new(owner.view(0).unwrap()));
    // Original J314s RegMap0/RegMap5b placements.
    bus.map(clock, 0x28e000000, 0x80000, 0).unwrap();
    bus.map(pmgr, 0x28e080000, 0x80000, 0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 1, &mut pins);
    for index in 0..4 {
        let address = 0x28e000000 + ISP_CLOCK_BASE + index * 4;
        assert_eq!(bus.read(address, Width::Word, &mut access), Ok(0x4000));
        // Four source/divider fields are requests, not a derived
        // camera frequency or a completed PLL/ISP transition.
        let written = 0x80004000 | (index << 24) | (index + 1);
        bus.write(address, Width::Word, written, &mut access)
            .unwrap();
        assert!(bus.read(address, Width::Word, &mut access).is_err());
        assert_eq!(
            owner.requests()[index as usize].kind,
            RequestKind::IspReferenceClock {
                clock: index as u8,
                source: index as u8,
                divider: index as u8 + 1,
            }
        );
    }
    let prefix = owner.requests();
    let observations = owner.observations();
    assert!(
        bus.write(0x28e038210, Width::Word, 0x80004000, &mut access)
            .is_err()
    );
    let view = bus.device_mut::<View>(pmgr).unwrap();
    view.set_lifecycle(
        LifecycleState {
            quiesced: true,
            ..LIVE
        },
        &mut access,
    );
    assert_eq!(bus.advance(&mut access), Ok(None));
    bus.device_mut::<View>(clock)
        .unwrap()
        .set_lifecycle(LIVE, &mut access);
    assert!(bus.advance(&mut access).is_err());
    assert_eq!(owner.requests(), prefix);
    assert_eq!(owner.observations(), observations);
}
#[test]
fn incomplete_or_stale_snapshot_cannot_replace_owned_work() {
    assert!(matches!(
        Controller::from_observations(vec![FULL], LIVE, []),
        Err(Error::MissingObservation)
    ));
    let mut observations = words(&[FULL], 0);
    observations.push(observations[0]);
    assert!(matches!(
        Controller::from_observations(vec![FULL], LIVE, observations),
        Err(Error::DuplicateObservation)
    ));
    let owner = controller(&[FULL], 0);
    let mut view = owner.view(0).unwrap();
    let mut pins = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut pins);
    view.write(CIO, Width::Word, 1, &mut access).unwrap();
    let prefix = owner.requests();
    let observations = owner.observations();
    owner.0.borrow_mut().serial = u64::MAX;
    assert!(view.write(CIO, Width::Word, 2, &mut access).is_err());
    assert_eq!(owner.requests(), prefix);
    assert_eq!(owner.observations(), observations);
}
