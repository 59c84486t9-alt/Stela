use super::super::{Bank, Instance, Observation as RequestObservation};
use super::*;
use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
use alloc::boxed::Box;
use {
    crate::platform::apple::pmgr::install::Action,
    crate::platform::apple::pmgr::install::NativeImage,
    crate::platform::apple::pmgr::install::Outcome, crate::platform::apple::pmgr::install::t6000,
    stela_contracts::bus::Bus, stela_contracts::bus::DeviceId, stela_contracts::dma::Memory,
    stela_contracts::interrupt::InterruptLatch,
};

const LIVE: LifecycleState = LifecycleState {
    powered: true,
    clocked: true,
    quiesced: false,
    reset: false,
    retention: true,
};
fn owner(handoff: Handoff) -> Controller {
    let geometry = Instance {
        complexes: 7,
        cio_ports: 15,
        cpm_controls: 7,
        isp_clocks: 7,
    };
    // Explicit supplied test request observations; these are not Apple
    // cold-state measurements or outputs of native initialization.
    let words = [Bank::Pmgr, Bank::ClkGenSoc].into_iter().flat_map(|bank| {
        geometry
            .offsets(bank)
            .into_iter()
            .map(move |offset| RequestObservation {
                instance: 0,
                bank,
                offset,
                value: 0,
                known: u32::MAX,
            })
    });
    Controller::with_native(vec![geometry], LIVE, words, handoff).unwrap()
}
fn mount(owner: &Controller) -> (Bus, DeviceId, DeviceId) {
    let mut bus = Bus::new();
    let controls = bus.add(Box::new(owner.native_controls().unwrap()));
    for row in super::controls() {
        bus.map(controls, row.address, 4, row.address).unwrap();
    }
    let sram = bus.add(Box::new(owner.native_sram().unwrap()));
    bus.map(sram, SRAM_BASE, SRAM_LIMIT - SRAM_BASE, 0).unwrap();
    let request = bus.add(Box::new(owner.view(0).unwrap()));
    bus.map(request, 0x28e098000, 12, 0x18000).unwrap();
    (bus, controls, sram)
}
fn images() -> Vec<NativeImage> {
    t6000::sequences()
        .into_iter()
        .filter(|row| !row.shared)
        .map(|row| NativeImage {
            sequence: row.id,
            counted_words: 1,
            bytes: [0xa0000000 | u32::from(row.id), 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        })
        .collect()
}
#[test]
fn publication_reaches_shared_controls_and_sram_not_a_parallel_capture_bank() {
    let owner = owner(Handoff::StelaEmpty {
        sram: SramInitialization::Unknown,
    });
    let (mut bus, _, _) = mount(&owner);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    assert_eq!(controls().len(), 43);
    let mut install = t6000::programs(0x20, Some(0), images()).unwrap();
    while let Some(claim) = install.begin().unwrap() {
        let action = install.dispatch(&claim).unwrap();
        let outcome = match action {
            Action::Read { address, width } => match bus.read(address, width, &mut access) {
                Ok(value) => Outcome::Read(value),
                Err(error) => Outcome::Uncertain(error),
            },
            Action::Write(write) => {
                match bus.write(write.address, write.width, write.value, &mut access) {
                    Ok(()) => Outcome::Written,
                    Err(error) => Outcome::Uncertain(error),
                }
            }
            Action::DmbSy => panic!("no source barrier in this publication phase"),
        };
        install.finish(&claim, outcome).unwrap();
    }
    assert!(install.published());
    let observations = owner.native_observations().unwrap();
    assert_eq!(observations.epoch, 302); // explicit initialization plus301 physical writes
    assert!(owner.requests().is_empty());
    assert!(owner.captured_pending().is_empty());
    let mut memory = owner.native_memory().unwrap();
    for placement in install.placements() {
        let entry = owner.native_entry(placement.group, placement.slot).unwrap();
        assert_eq!(entry.pc, placement.code);
        let mut pointer = [0; 8];
        assert!(memory.read(entry.pointer, &mut pointer));
        assert_eq!(u64::from_le_bytes(pointer), entry.pc >> 4);
        let mut code = [0; 4];
        assert!(memory.read(entry.pc, &mut code));
        assert_eq!(
            bus.read(entry.pc, Width::Word, &mut access),
            Ok(u64::from(u32::from_le_bytes(code)))
        );
    }
    let mut unknown = [0xa5; 8];
    assert!(!memory.read(CODE_BASE + 8, &mut unknown));
    assert_eq!(unknown, [0xa5; 8]);
    assert_eq!(owner.native_entry(2, 6), Err(Error::UnknownSram));
    // Both APIs address the same bytes and knownness plane.
    assert!(memory.write(CODE_BASE + 1, &[0x12, 0x34]));
    assert_eq!(
        bus.read(CODE_BASE, Width::Word, &mut access),
        Ok(0xa0341200)
    );
    assert_eq!(bus.read(GPCE + 0x68, Width::Word, &mut access), Ok(2));
    // No pointer lookup admits execution or manufactures an interrupt.
    assert!(sink.take_aic_inputs().is_empty());
}
#[test]
fn kept_views_share_lifecycle_and_pending_requests_prevent_code_replacement() {
    let owner = owner(Handoff::StelaEmpty {
        sram: SramInitialization::Unknown,
    });
    let (mut bus, _, sram) = mount(&owner);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 11, &mut sink);
    bus.write(CODE_BASE, Width::Word, 0x12345678, &mut access)
        .unwrap();
    let mut memory = owner.native_memory().unwrap();
    let mut paused = LIVE;
    paused.quiesced = true;
    bus.device_mut::<View>(sram)
        .unwrap()
        .set_lifecycle(paused, &mut access);
    assert_eq!(owner.lifecycle(), paused);
    // Quiesce suspends execution, while the supplied configuration bus is held.
    assert_eq!(
        bus.read(CODE_BASE, Width::Word, &mut access),
        Ok(0x12345678)
    );
    paused.clocked = false;
    bus.device_mut::<View>(sram)
        .unwrap()
        .set_lifecycle(paused, &mut access);
    assert!(bus.read(CODE_BASE, Width::Word, &mut access).is_err());
    assert!(!memory.write(CODE_BASE, &[0; 4]));
    paused.powered = false;
    bus.device_mut::<View>(sram)
        .unwrap()
        .set_lifecycle(paused, &mut access);
    bus.device_mut::<View>(sram)
        .unwrap()
        .set_lifecycle(LIVE, &mut access);
    assert_eq!(
        bus.read(CODE_BASE, Width::Word, &mut access),
        Ok(0x12345678)
    );
    bus.write(0x28e098000, Width::Word, 15, &mut access)
        .unwrap();
    let request = owner.requests();
    let before = owner.native_observations().unwrap();
    assert!(bus.write(CODE_BASE, Width::Word, 0, &mut access).is_err());
    assert!(bus.write(GPCE + 0x40, Width::Word, 0, &mut access).is_err());
    assert_eq!(
        memory.write_checked(CODE_BASE, &[0; 4]),
        Err(Error::Pending)
    );
    assert_eq!(owner.native_observations().unwrap().epoch, before.epoch);
    assert_eq!(owner.requests(), request);
    assert!(bus.advance(&mut access).is_err()); // trigger/PC/retirement still unknown
    let mut reset = LIVE;
    reset.reset = true;
    assert!(
        bus.device_mut::<View>(sram)
            .unwrap()
            .check_lifecycle(reset)
            .is_err()
    );
    reset.reset = false;
    reset.powered = false;
    reset.retention = false;
    assert!(
        bus.device_mut::<View>(sram)
            .unwrap()
            .check_lifecycle(reset)
            .is_err()
    );
    assert_eq!(owner.lifecycle(), LIVE);
    assert_eq!(
        bus.read(CODE_BASE, Width::Word, &mut access),
        Ok(0x12345678)
    );
}
#[test]
fn observed_unknownness_duplicate_evidence_and_atomic_physical_bounds_are_preserved() {
    let owner = owner(Handoff::Observed {
        controls: ACTIVATION_WORDS
            .into_iter()
            .map(|(address, _)| Observation {
                address,
                value: 0,
                known: u32::MAX,
            })
            .chain([Observation {
                address: GPCE + 0x40,
                value: 3,
                known: 31,
            }])
            .collect(),
        sram: vec![Fragment {
            offset: (CODE_BASE - SRAM_BASE) as usize,
            bytes: vec![1, 2, 3, 4],
        }],
    });
    let (mut bus, _, _) = mount(&owner);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    assert!(bus.read(GPCE + 0x40, Width::Word, &mut access).is_err());
    assert!(bus.write(GPCE + 0x40, Width::Word, 4, &mut access).is_err());
    let mut memory = owner.native_memory().unwrap();
    let mut output = [0xa5; 8];
    assert!(!memory.read(CODE_BASE, &mut output));
    assert_eq!(output, [0xa5; 8]);
    assert!(memory.write(SRAM_LIMIT - 4, &[1, 2, 3, 4]));
    assert!(!memory.write(SRAM_LIMIT - 4, &[9; 8]));
    assert!(memory.read(SRAM_LIMIT - 4, &mut output[..4]));
    assert_eq!(&output[..4], &[1, 2, 3, 4]);
    assert!(matches!(
        State::new(Handoff::Observed {
            controls: vec![
                Observation {
                    address: GPCE,
                    value: 0,
                    known: 0
                },
                Observation {
                    address: GPCE,
                    value: 0,
                    known: 0
                },
            ],
            sram: vec![]
        }),
        Err(Error::DuplicateControl)
    ));
    assert!(matches!(
        State::new(Handoff::Observed {
            controls: vec![],
            sram: vec![
                Fragment {
                    offset: 0,
                    bytes: vec![1, 2]
                },
                Fragment {
                    offset: 1,
                    bytes: vec![2, 3]
                },
            ]
        }),
        Err(Error::DuplicateByte)
    ));
    assert_eq!(owner.native_entry(10, 0), Err(Error::Group));
    assert_eq!(owner.native_entry(2, 32), Err(Error::Slot));
}
#[test]
fn explicit_whole_zero_policy_never_supplies_other_device_status_or_accepts_unknown_fields() {
    let owner = owner(Handoff::StelaEmpty {
        sram: SramInitialization::Zeroed,
    });
    let (mut bus, _, _) = mount(&owner);
    let mut memory = owner.native_memory().unwrap();
    let mut whole = vec![0xa5; SRAM_BYTES];
    assert!(memory.read(SRAM_BASE, &mut whole));
    assert!(whole.iter().all(|byte| *byte == 0));
    let before = owner.native_observations().unwrap();
    assert_eq!(
        before.stela_initialization,
        Some(SramInitialization::Zeroed)
    );
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    assert!(
        bus.write(GPCE + 0x40, Width::Word, 1 << 31, &mut access)
            .is_err()
    );
    assert_eq!(owner.native_observations().unwrap().epoch, before.epoch);
    assert!(owner.requests().is_empty());
    assert!(owner.native_entry(2, 0).is_err()); // zeros are not a ready/running program
    owner.0.borrow_mut().native.as_mut().unwrap().epoch = u64::MAX;
    assert_eq!(memory.write_checked(SRAM_BASE, &[1]), Err(Error::Epoch));
    assert_eq!(bus.read(SRAM_BASE, Width::Byte, &mut access), Ok(0));
}

#[test]
fn frozen_sram_routes_effects_through_the_controller() {
    use crate::platform::apple::pmgr::sequencer::{self, AddressFormat, RouteOutcome, poll};
    let owner = owner(Handoff::StelaEmpty {
        sram: SramInitialization::Unknown,
    });
    let (mut bus, controls, _) = mount(&owner);
    let cpm = bus.add(Box::new(owner.view(0).unwrap()));
    bus.map(cpm, 0x28e09c0c0, 4, 0x1c0c0).unwrap();
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    // Explicit supplied emitter-format test program: disable CPM, poll its
    // input bit clear, then submit a real GPCE target. End remains
    // unchecked; none of these effects acknowledges native completion.
    let words = [
        0x28e09c01, 0, 0x30, 0, 0x28e09c02, 0, 0x30, 0x80000000, 0, 0x28e09801, 0, 0, 15, 0,
    ];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut supplied = images();
    let image = supplied.iter_mut().find(|row| row.sequence == 12).unwrap();
    image.counted_words = words.len() as u32 - 1;
    image.bytes = bytes.clone();
    let mut installation = t6000::programs(0x20, Some(0), supplied).unwrap();
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
    let entry = owner.native_entry(2, 0).unwrap();
    let mut effects = owner
        .native_packet_effects(
            2,
            0,
            bytes.len(),
            AddressFormat::HighWord,
            Some(test_initial()),
        )
        .unwrap();
    assert!(matches!(
        owner.native_packet_effects(
            2,
            0,
            bytes.len(),
            AddressFormat::HighWord,
            Some(test_initial())
        ),
        Err(Error::EffectsOwned)
    ));
    let mut memory = owner.native_memory().unwrap();
    assert_eq!(memory.write_checked(entry.pc, &[0; 4]), Err(Error::Pending));
    assert!(owner.native_observations().unwrap().packet_effects_owned);
    let write = effects.begin_write().unwrap();
    let actual = effects
        .dispatch_write(&write, &write.qualify_context(test_fields()).unwrap())
        .unwrap();
    bus.write(actual.address, actual.width, actual.value, &mut access)
        .unwrap();
    effects
        .finish_write::<()>(&write, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(
        effects.begin_write().unwrap_err(),
        sequencer::Error::ExpectedWrite
    );
    let read = effects.begin_read().unwrap();
    let mut paused = LIVE;
    paused.quiesced = true;
    bus.device_mut::<View>(controls)
        .unwrap()
        .set_lifecycle(paused, &mut access);
    assert_eq!(
        effects.dispatch_read(&read, &read.qualify_context(test_fields()).unwrap()),
        Err(sequencer::Error::Suspended)
    );
    bus.device_mut::<View>(controls)
        .unwrap()
        .set_lifecycle(LIVE, &mut access);
    let actual = effects
        .dispatch_read(&read, &read.qualify_context(test_fields()).unwrap())
        .unwrap();
    let value = bus.read(actual.address, actual.width, &mut access).unwrap();
    paused.clocked = false;
    bus.device_mut::<View>(controls)
        .unwrap()
        .set_lifecycle(paused, &mut access);
    assert_eq!(
        effects.finish_read::<()>(&read, poll::Outcome::Read(value)),
        Ok(true)
    );
    assert_eq!(
        effects.begin_write().unwrap_err(),
        sequencer::Error::Suspended
    );
    bus.device_mut::<View>(controls)
        .unwrap()
        .set_lifecycle(LIVE, &mut access);
    let write = effects.begin_write().unwrap();
    let actual = effects
        .dispatch_write(&write, &write.qualify_context(test_fields()).unwrap())
        .unwrap();
    bus.write(actual.address, actual.width, actual.value, &mut access)
        .unwrap();
    effects
        .finish_write::<()>(&write, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(
        (effects.committed_writes(), effects.committed_reads()),
        (2, 1)
    );
    assert_eq!(
        effects.begin_read().unwrap_err(),
        sequencer::Error::UnqualifiedRetirement
    );
    assert_eq!(owner.requests().len(), 2); // disable input and GPCE target
    let gpce = owner
        .observations()
        .into_iter()
        .find(|word| word.offset == 0x18000)
        .unwrap();
    assert_eq!(gpce.value & 15, 15);
    assert_eq!(gpce.known & 0x70, 0); // no readiness invented by a matched poll
    let mut retained = vec![0; bytes.len()];
    memory.read_checked(entry.pc, &mut retained).unwrap();
    assert_eq!(retained, bytes);
    drop(effects);
    assert_eq!(memory.write_checked(entry.pc, &[0; 4]), Err(Error::Pending));
    assert!(sink.take_aic_inputs().is_empty());
}

#[test]
fn sram_delay_uses_shared_native_clock_with_distinct_quiesce_and_supply_pauses() {
    use crate::platform::apple::{
        pmgr::sequencer::{self, AddressFormat, RouteOutcome, delay::Progress},
        power::t6000::clock,
    };
    for pause in 0..3 {
        let owner = owner(Handoff::StelaEmpty {
            sram: SramInitialization::Unknown,
        });
        let (mut bus, controls, _) = mount(&owner);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        // Source-format supplied test program: GPCE request, wait
        // three native cycles, then end. No request or end ACK follows.
        let words = [0x28e09801, 0, 0, 15, 4 | (3 << 6), 0];
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut supplied = images();
        let image = supplied
            .iter_mut()
            .find(|image| image.sequence == 12)
            .unwrap();
        image.counted_words = words.len() as u32 - 1;
        image.bytes = bytes.clone();
        let mut install = t6000::programs(0x20, Some(0), supplied).unwrap();
        while let Some(claim) = install.begin().unwrap() {
            let outcome = match install.dispatch(&claim).unwrap() {
                Action::Read { address, width } => {
                    Outcome::<MmioError>::Read(bus.read(address, width, &mut access).unwrap())
                }
                Action::Write(write) => {
                    bus.write(write.address, write.width, write.value, &mut access)
                        .unwrap();
                    Outcome::Written
                }
                Action::DmbSy => panic!("publication has no barrier"),
            };
            install.finish(&claim, outcome).unwrap();
        }
        let mut effects = owner
            .native_packet_effects(
                2,
                0,
                bytes.len(),
                AddressFormat::HighWord,
                Some(test_initial()),
            )
            .unwrap();
        assert_eq!(effects.advance_delay(0), Err(Error::ClockUnbound));
        assert_eq!(effects.packet_kind(), Ok(sequencer::PacketKind::Write));
        let clock = clock::Image::new(clock::Input::DeclaredStela(
            clock::Register::ALL
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
                .collect(),
        ))
        .unwrap();
        assert_eq!(
            owner.bind_native_clock(clock.clone(), clock::Phase::Unknown),
            Err(Error::Clock(clock::Error::UnknownPhase))
        );
        owner
            .bind_native_clock(
                clock.clone(),
                clock::Phase::DeclaredStela {
                    at: 0,
                    cycles: 0,
                    fraction: 0,
                },
            )
            .unwrap();
        assert_eq!(
            owner.bind_native_clock(
                clock,
                clock::Phase::DeclaredStela {
                    at: 0,
                    cycles: 0,
                    fraction: 0
                }
            ),
            Err(Error::ClockBound)
        );
        let claim = effects.begin_write().unwrap();
        let write = effects
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        bus.write(write.address, write.width, write.value, &mut access)
            .unwrap();
        effects
            .finish_write::<()>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(owner.requests().len(), 1);
        assert_eq!(effects.packet_kind(), Ok(sequencer::PacketKind::Delay));
        assert_eq!(
            effects.advance_delay(0),
            Ok(Progress {
                remaining: 3,
                complete: false
            })
        );
        assert_eq!(
            effects.advance_delay(732),
            Ok(Progress {
                remaining: 3,
                complete: false
            })
        );
        assert_eq!(effects.delay_deadline(), Ok(Some(2198)));
        assert_eq!(owner.native_clock_observations().unwrap().frequency, 32768);
        let mut paused = LIVE;
        match pause {
            0 => paused.clocked = false,
            1 => paused.powered = false,
            _ => paused.quiesced = true,
        };
        access.now = 732;
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        assert_eq!(
            effects.advance_delay(1732),
            Err(Error::Cursor(sequencer::Error::Suspended))
        );
        assert_eq!(effects.delay_deadline(), Ok(None));
        let clock = owner.native_clock_observations().unwrap();
        assert_eq!(clock.cycles, if pause == 2 { 2 } else { 0 });
        access.now = 1732;
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        let resume = effects.advance_delay(1732).unwrap();
        assert_eq!(resume.remaining, if pause == 2 { 1 } else { 3 });
        let finish = if pause == 2 { 2198 } else { 3198 };
        assert_eq!(effects.delay_deadline(), Ok(Some(finish)));
        assert_eq!(
            effects.advance_delay(finish - 1),
            Ok(Progress {
                remaining: 1,
                complete: false
            })
        );
        assert_eq!(
            effects.advance_delay(finish),
            Ok(Progress {
                remaining: 0,
                complete: true
            })
        );
        assert_eq!(
            effects.advance_delay(finish),
            Err(Error::Cursor(sequencer::Error::UnqualifiedRetirement))
        );
        assert_eq!(owner.requests().len(), 1);
        assert_eq!(effects.committed_writes(), 1);
        assert_eq!(
            effects.packet_kind(),
            Err(sequencer::Error::UnqualifiedRetirement)
        );
        assert!(owner.native_observations().unwrap().packet_effects_owned);
        assert!(
            bus.device_mut::<View>(controls)
                .unwrap()
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..LIVE
                })
                .is_err()
        );
    }
}

#[test]
fn clock_adoption_cannot_backdate_over_prior_rail_edges_or_erase_time_faults() {
    use crate::platform::apple::power::t6000::clock;
    let owner = owner(Handoff::StelaEmpty {
        sram: SramInitialization::Unknown,
    });
    let mut view = owner.native_controls().unwrap();
    let mut pins = InterruptLatch::new();
    view.set_lifecycle(
        LifecycleState {
            clocked: false,
            ..LIVE
        },
        &mut Access::new(0, 100, &mut pins),
    );
    let image = clock::Image::new(clock::Input::DeclaredStela(
        clock::Register::ALL
            .into_iter()
            .map(|register| clock::Observation {
                register,
                value: 0,
                known: u32::MAX,
            })
            .collect(),
    ))
    .unwrap();
    assert_eq!(
        owner.bind_native_clock(
            image.clone(),
            clock::Phase::DeclaredStela {
                at: 0,
                cycles: 0,
                fraction: 0
            }
        ),
        Err(Error::Clock(clock::Error::PhaseHistory))
    );
    owner
        .bind_native_clock(
            image.clone(),
            clock::Phase::DeclaredStela {
                at: 100,
                cycles: 0,
                fraction: 0,
            },
        )
        .unwrap();
    view.set_lifecycle(LIVE, &mut Access::new(0, 99, &mut pins));
    let observed = owner.native_clock_observations().unwrap();
    assert_eq!(observed.fault, Some(clock::Error::Regressed));
    assert_eq!((observed.at, observed.cycles), (100, 0));
    assert!(
        view.check_lifecycle(LifecycleState {
            quiesced: true,
            ..LIVE
        })
        .is_err()
    );
    assert_eq!(
        owner.bind_native_clock(
            image,
            clock::Phase::DeclaredStela {
                at: 100,
                cycles: 0,
                fraction: 0
            }
        ),
        Err(Error::ClockBound)
    );
}
