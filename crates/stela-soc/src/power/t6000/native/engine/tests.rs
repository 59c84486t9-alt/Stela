use super::*;
use crate::pmgr::sequencer::control::{test_fields, test_initial};
use alloc::boxed::Box;
use {
    crate::pmgr::install::Action, crate::pmgr::install::NativeImage, crate::pmgr::install::Outcome,
    crate::pmgr::install::t6000, crate::pmgr::sequencer::FinishError, crate::pmgr::sequencer::copy,
    crate::pmgr::sequencer::poll, crate::power::t6000::Instance, crate::power::t6000::Observation,
    crate::power::t6000::clock, stela_contracts::bus::Access, stela_contracts::bus::Bus,
    stela_contracts::bus::DeviceId, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::interrupt::InterruptLatch,
};

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
        0, // CPM disable input
        0x28e09c02,
        0,
        0x30,
        0x80000000,
        0,            // poll CPM input
        4 | (3 << 6), // three native cycles
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
        stela_soc_data::pmgr::t6000::SRAM_BASE,
        stela_soc_data::pmgr::t6000::SRAM_LIMIT - stela_soc_data::pmgr::t6000::SRAM_BASE,
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
            let words = if let Some(port) = [36, 40, 44, 48].iter().position(|id| *id == row.id) {
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
                .map_or_else(|| program(port).len(), Vec::len) as u32
                - 1,
            format: AddressFormat::HighWord,
        })
        .collect();
    if let Some((address, bytes)) = data {
        // Explicit initialization, before the shared native image is
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
fn mounted_requests_retire_only_after_end() {
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
fn canonical_source_copy_keeps_bytes_across_pause_and_destination_refusal() {
    const SOURCE: u64 = stela_soc_data::pmgr::t6000::SRAM_BASE + 0x60000;
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
        1 << 16, // controller action
        0,
    ];
    let (owner, mut bus, requests) = fixture_with_data(Some(words), true, Some((SOURCE, &bytes)));
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
    // immutable native code/source SRAM. Commit follows its store.
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
fn mounted_control_context_changes_survive_pause_and_require_exact_route_acceptance() {
    let words = vec![
        0x30001c, // source18000, fields[0,0,0,3,0]
        0x28e09c01,
        0,
        0x30,
        0,    // CPM disable
        0x1c, // source0, independently updates context
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
fn later_native_job_inherits_retired_context_instead_of_replaying_entry_input() {
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
fn stride_packet_retires_each_controller_write_before_cio_end() {
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
    // completion permission. That error must not authorize a second write.
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
fn action_before_later_effects_keeps_in_flight_generation_and_cannot_publish_completion() {
    let words = vec![
        0x28e09a01,
        0,
        0xd,
        1 << 16, // action arrives before later work
        0x28e09c01,
        0,
        0x30,
        0, // CPM write still required
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
fn invalid_programs_keep_pending_state() {
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
fn quiesce_keeps_the_job_and_delay_progress() {
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
#[ignore = "oracle: STELA_TEST_PMGR_M1_IBOOTDATA, STELA_TEST_PMGR_M1_KERNELCACHE, STELA_TEST_PMGR_M1_LLB"]
fn original_cio_request_wait_bindings_actions_and_counted_finalization_are_pinned() {
    use sha2::{Digest, Sha256};
    let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
    let kernel = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
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
    let word =
        |bytes: &[u8], offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    assert_eq!(word(&kernel, 0x2b4b0fc), 0x6a15001f); // TST read/mask
    assert_eq!(word(&kernel, 0x2b4b100), 0x54000500); // exit when high bit CLEAR
    assert_eq!(word(&llb, 0x11574), 0xb8286abf); // zero terminator store
    assert_eq!(word(&llb, 0x115b8), 0x6b0802bf); // compare counted/emitted words
    // A control instruction exists even with source control0. Its
    // flag/handshake effects are not treated as a no-op.
    assert_eq!(word(&llb, 0x107c8), 0x321e0929);
}
