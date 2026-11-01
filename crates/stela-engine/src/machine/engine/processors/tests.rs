use super::super::tests::{BASE, FakeHost, board};
use super::*;
use stela_contracts::refuse;
use {
    crate::machine::cpu::Reservation, crate::machine::engine::DeviceError,
    crate::machine::exception::DAIF_ALL, crate::machine::system::Register,
    stela_contracts::identity::Identity,
};

const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const START: u64 = BASE + 0x800;

/// Devices that start PEs on request and drive one IRQ line per PE.
#[derive(Default)]
struct Board {
    starts: Vec<Start>,
    irq: [bool; 2],
    lines_asked: Vec<usize>,
    dma: Option<u64>,
    /// Every PE's reset vector.
    reset: Option<u64>,
    /// The power-downs and power-ups the engine reported.
    power: Vec<(usize, bool)>,
    /// Something outside the board can still wake a PE.
    host_wake: bool,
    /// It has moved bytes the host feeds since the engine last asked.
    host_service: bool,
    /// The counts its lines and deadlines were asked at, in order.
    counts: Vec<u64>,
    /// It answers `Devices::pins`, and the PEs that asked.
    pins: bool,
    pins_asked: Vec<usize>,
}

impl Board {
    /// Same synchronous call order required of the real PMGR adapter.
    fn retained_write(
        &mut self,
        processors: ProcessorWrite<'_>,
        changes: &[ProcessorChange],
        refuse_native: bool,
        events: &mut Vec<&'static str>,
    ) -> Result<(), DeviceError> {
        events.push("native preflight");
        if refuse_native {
            return Err(DeviceError::TransferRefused(
                "native preflight refused".into(),
            ));
        }
        let settled = processors.apply(changes).map_err(|why| {
            DeviceError::TransferRefused(refuse!("processor transaction: {why}", ?why))
        })?;
        // These are owners, still exclusively borrowed through ACK.
        assert_eq!(settled.paused(0), Some(true));
        assert_eq!(settled.paused(1), Some(true));
        assert!(settled.owners.cpu.monitor.is_none());
        let Peer::Parked(peer) = &settled.owners.peers[1] else {
            panic!("actual parked owner")
        };
        assert!(peer.cpu.monitor.is_none());
        assert!(settled.owners.native.timers.is_none());
        assert!(settled.owners.native.device_lines.is_none());
        assert_eq!(
            *settled.owners.native.mirrors,
            super::super::Mirrors::default()
        );
        assert!(settled.owners.native.prediction_context.is_some());
        events.push("CPU and native dispatch settled");
        events.push("native commit");
        events.push("controller ACK");
        Ok(())
    }
}

impl Devices for Board {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
        self.lines_asked.push(cpu);
        self.counts.push(now);
        Lines {
            irq: self.irq[cpu],
            fiq: false,
        }
    }
    fn pins(&mut self, cpu: usize) -> Option<Lines> {
        self.pins_asked.push(cpu);
        self.pins.then(|| Lines {
            irq: self.irq[cpu],
            fiq: false,
        })
    }
    fn dma_deadline(&self) -> Option<u64> {
        self.dma
    }
    fn deadline(&mut self, now: u64) -> Option<u64> {
        self.counts.push(now);
        None
    }
    fn transfer(
        &mut self,
        _: usize,
        memory: &mut dyn stela_contracts::dma::Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
        if self.dma.is_some_and(|deadline| now >= deadline) {
            if !memory.write(BASE + 0x100, b"USB") {
                return Err(DeviceError::Refused("test DMA RAM unavailable".into()));
            }
            self.dma = None;
            self.irq[0] = true;
        }
        Ok(())
    }
    fn take_start(&mut self) -> Option<Start> {
        self.starts.pop()
    }
    fn reset_vector(&self, _: usize) -> Option<u64> {
        self.reset
    }
    fn processor_power(&mut self, cpu: usize, on: bool) {
        self.power.push((cpu, on));
    }
    fn waits_on_host(&self) -> bool {
        self.host_wake
    }
    fn take_host_service(&mut self) -> bool {
        core::mem::take(&mut self.host_service)
    }
}

fn identity(cpu: u64) -> Identity {
    Identity {
        midr: 0x611f_0320 | cpu << 4,
        mpidr: 0x8000_0000 | cpu << 8,
        clock: None,
        caches: None,
    }
}

#[test]
fn a_nonzero_boot_processor_keeps_resource_indices_and_secondary_reset_state() {
    let mut prepared = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
    prepared.cpu.state.x[0] = 0x1234_5678;
    prepared.cpu.state.sp = BASE + 0x400;
    let state = prepared.cpu.state.clone();
    let pc = prepared.cpu.pc;
    let mut machine = Machine::new_at(
        prepared.cpu,
        prepared.host,
        prepared.devices,
        prepared.profile,
        prepared.target,
        1,
    )
    .unwrap();
    assert_eq!(machine.processor(), 1);
    assert!(matches!(machine.peers[0], Peer::Off));
    assert!(matches!(machine.peers[1], Peer::Running));
    assert_eq!(machine.cpu.state, state);
    assert_eq!(machine.cpu.pc, pc);
    assert_eq!(machine.cpu.read(Register::MIDR_EL1), identity(1).midr);
    assert_eq!(machine.cpu.read(Register::MPIDR_EL1), identity(1).mpidr);
    assert_eq!(machine.profile.processors, [identity(0), identity(1)]);
    assert!(machine.devices.power.is_empty());
    machine.devices.starts.push(Start {
        cpu: 0,
        address: START,
    });
    machine.take_starts().unwrap();
    assert_eq!(parked(&machine, 0).pc, START);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    assert_eq!(machine.cpu.pc, START);
    assert_eq!(machine.cpu.read(Register::MPIDR_EL1), identity(0).mpidr);
    assert_eq!(parked(&machine, 1).state, state);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert_eq!(machine.cpu.state, state);
    assert_eq!(machine.cpu.pc, pc);
}

#[test]
fn a_boot_processor_outside_the_profile_is_refused() {
    for selected in [2, usize::MAX] {
        let prepared = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
        assert!(
            Machine::new_at(
                prepared.cpu,
                prepared.host,
                prepared.devices,
                prepared.profile,
                prepared.target,
                selected,
            )
            .is_err()
        );
    }
}

/// Two PEs, PE 1 started at START and both runnable, PE 0 running.
fn pair() -> Machine<FakeHost, Board> {
    let devices = Board {
        starts: alloc::vec![Start {
            cpu: 1,
            address: START,
        }],
        ..Board::default()
    };
    let mut machine = board(&[], devices, alloc::vec![identity(0), identity(1)]);
    machine.schedule().unwrap();
    machine
}

#[test]
fn retirement_totals_count_live_parked_and_replaced_cpus_once() {
    let mut machine = pair();
    let other = 1 - machine.current;
    machine.cpu.retired = 11;
    let Peer::Parked(parked) = &mut machine.peers[other] else {
        panic!("parked peer")
    };
    parked.cpu.retired = 7;
    parked.waiting = Some(Wait {
        kind: WaitKind::Interrupt,
        timeout: None,
        down: true,
    });
    assert_eq!(machine.retired_instructions(), 18);
    assert!(
        machine
            .start(Start {
                cpu: machine.current,
                address: START
            })
            .is_err()
    );
    assert_eq!(machine.retired_instructions(), 18);
    machine.restart(other, START).unwrap();
    assert_eq!(machine.retired_instructions(), 18);
    let Peer::Parked(parked) = &mut machine.peers[other] else {
        panic!("parked peer")
    };
    parked.cpu.retired = 5;
    assert_eq!(machine.retired_instructions(), 23);
    machine.switch_to(other);
    assert_eq!(machine.retired_instructions(), 23);
    machine.restart(other, START).unwrap();
    assert_eq!(machine.retired_instructions(), 23);
    machine.cpu.retired = 3;
    machine.devices.reset = Some(START);
    machine.warm_reset().unwrap();
    assert_eq!(machine.retired_instructions(), 26);
}

#[test]
fn a_switch_keeps_cached_translations_only_between_pes_that_translate_alike() {
    let mut machine = pair();
    let (first, other) = (machine.current, 1 - machine.current);
    let (generation, tables) = (machine.translation_generation, machine.table_generation);
    machine.switch_to(other);
    assert_eq!(machine.translation_generation, generation);
    assert_eq!(machine.statistics.translation_changes, 0);
    let Peer::Parked(parked) = &mut machine.peers[first] else {
        panic!("parked peer")
    };
    parked.cpu.registers.set(Register::TTBR0_EL1, 0, 0x4000);
    // What derives from the outgoing PE's registers goes with it.
    machine.floating_point = Some(None);
    machine.switch_to(first);
    assert_eq!(machine.floating_point, None);
    assert!(machine.table_generation > tables);
    assert_eq!(machine.statistics.table_base_changes, 1);
    assert_eq!(machine.statistics.translation_changes, 0);
    let Peer::Parked(parked) = &mut machine.peers[other] else {
        panic!("parked peer")
    };
    parked.cpu.registers.set(Register::TTBR1_EL1, 0, 0x8000);
    machine.switch_to(other);
    assert_eq!(machine.statistics.translation_changes, 1);
}

fn end_slice(machine: &mut Machine<FakeHost, Board>) {
    machine.slice_end = machine.statistics.blocks;
}

fn parked(machine: &Machine<FakeHost, Board>, pe: usize) -> &Cpu {
    match &machine.peers[pe] {
        Peer::Parked(parked) => &parked.cpu,
        _ => panic!("PE {pe} is not parked"),
    }
}

const RETAINED_ACTIVE: stela_contracts::bus::LifecycleState =
    stela_contracts::bus::LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: false,
    };
const RETAINED_GATED: stela_contracts::bus::LifecycleState = stela_contracts::bus::LifecycleState {
    clocked: false,
    ..RETAINED_ACTIVE
};

fn core_binding(domain: u64, pe: usize) -> ProcessorBinding {
    ProcessorBinding {
        domain,
        target: ProcessorTarget::Core { pe },
        initial: RETAINED_ACTIVE,
    }
}

fn power_change(
    machine: &mut Machine<FakeHost, Board>,
    domain: u64,
    state: stela_contracts::bus::LifecycleState,
) {
    let plan = machine
        .prepare_processor_power(&[ProcessorChange { domain, state }])
        .unwrap();
    machine.settle_processor_power(plan).unwrap();
}

#[test]
fn kept_gates_pause_live_and_parked_owners_without_consuming_pending_state() {
    let mut machine = pair();
    machine
        .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
        .unwrap();
    machine.cpu.state.x[5] = 0x1234;
    machine.cpu.state.v[3] = [0x1234, 0x5678];
    machine.cpu.state.fpcr = 1 << 25;
    machine.cpu.state.fpsr = 1 << 27;
    let state = machine.cpu.state.clone();
    machine.cpu.amx.registers = Some(Box::new(stela_compiler::amx::AmxRegisters::zeroed()));
    machine.cpu.amx.registers.as_mut().unwrap().z[42] = [0xa5; 64];
    let amx = machine.cpu.amx.registers.clone();
    machine.cpu.event = true;
    machine.cpu.monitor = Some(Reservation {
        granule: BASE,
        bytes: [0; RESERVATION_GRANULE as usize],
    });
    let cluster = machine.cpu.ctrr.clone();
    let Peer::Parked(other) = &mut machine.peers[1] else {
        panic!("PE1 parked")
    };
    other.cpu.state.x[5] = 0x5678;
    other.cpu.state.v[7] = [0x9abc, 0xdef0];
    let other_state = other.cpu.state.clone();
    other.cpu.event = true;
    other.cpu.monitor = Some(Reservation {
        granule: BASE,
        bytes: [0; RESERVATION_GRANULE as usize],
    });
    let other_cluster = other.cpu.ctrr.clone();
    let plan = machine
        .prepare_processor_power(&[
            ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            },
            ProcessorChange {
                domain: 2,
                state: stela_contracts::bus::LifecycleState {
                    quiesced: true,
                    ..RETAINED_ACTIVE
                },
            },
        ])
        .unwrap();
    assert!(
        machine.cpu.monitor.is_some(),
        "preflight never clears reservations"
    );
    machine.settle_processor_power(plan).unwrap();
    machine.devices.irq = [true, true];
    assert_eq!(machine.runnable(), 0);
    assert!(!machine.ready(0, 100) && !machine.ready(1, 100));
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    assert_eq!(machine.cpu.state.x[5], 0x1234);
    assert_eq!(machine.cpu.state, state);
    assert_eq!(parked(&machine, 1).state, other_state);
    assert!(machine.cpu.amx.registers == amx);
    assert!(machine.cpu.event && parked(&machine, 1).event);
    assert!(machine.cpu.monitor.is_none() && parked(&machine, 1).monitor.is_none());
    assert!(cluster.ptr_eq(&machine.cpu.ctrr));
    assert!(other_cluster.ptr_eq(&parked(&machine, 1).ctrr));
    assert!(matches!(machine.peer_states()[0], PeerState::Parked { .. }));
    power_change(&mut machine, 2, RETAINED_ACTIVE);
    machine.schedule().unwrap();
    assert_eq!(
        (machine.processor(), machine.cpu.pc, machine.cpu.state.x[5]),
        (1, START, 0x5678)
    );
    assert!(machine.interrupt_pending());
    power_change(&mut machine, 1, RETAINED_ACTIVE);
    machine.schedule().unwrap();
    assert_eq!(
        (machine.processor(), machine.cpu.pc, machine.cpu.state.x[5]),
        (0, BASE, 0x1234)
    );
    assert_eq!(
        machine.devices.power,
        [(1, true)],
        "retained edges never request reset"
    );
}

#[test]
fn a_stale_settlement_cannot_touch_cpu_reservations_or_clock_accounting() {
    let mut machine = pair();
    machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
    let stale = machine
        .prepare_processor_power(&[ProcessorChange {
            domain: 1,
            state: RETAINED_GATED,
        }])
        .unwrap();
    power_change(&mut machine, 1, RETAINED_ACTIVE);
    machine.cpu.monitor = Some(Reservation {
        granule: BASE,
        bytes: [0; RESERVATION_GRANULE as usize],
    });
    machine.slice_end = 123;
    machine.host.now = 100;
    assert_eq!(
        machine.settle_processor_power(stale),
        Err(ProcessorPowerError::StalePlan)
    );
    assert!(machine.cpu.monitor.is_some());
    assert_eq!(machine.slice_end, 123);
    assert_eq!(machine.processors().paused(0), Some(false));
    assert_eq!(machine.statistics.switches, 0);
}

#[test]
fn every_owner_is_preflighted_before_any_kept_transaction_effect() {
    for broken in 0..3 {
        let mut machine = pair();
        machine
            .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
            .unwrap();
        let plan = machine
            .prepare_processor_power(&[ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            }])
            .unwrap();
        machine.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        machine.host.now = 100;
        machine.slice_end = 123;
        let expected = match broken {
            0 => {
                machine.peers.pop();
                ProcessorPowerError::OwnerCount {
                    expected: 2,
                    actual: 1,
                }
            }
            1 => {
                machine.peers[0] = Peer::Off;
                ProcessorPowerError::MissingLiveOwner(0)
            }
            _ => {
                machine.peers[1] = Peer::Running;
                ProcessorPowerError::UnexpectedLiveOwner(1)
            }
        };
        assert_eq!(machine.settle_processor_power(plan), Err(expected.clone()));
        assert_eq!(
            machine
                .prepare_processor_power(&[ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                }])
                .unwrap_err(),
            expected
        );
        assert!(machine.cpu.monitor.is_some());
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.slice_end, 123);
        assert_eq!(machine.statistics.translation_changes, 0);
    }
}

#[test]
fn synchronous_write_settles_pe_and_native_owners_before_controller_ack() {
    let mut machine = pair();
    machine
        .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
        .unwrap();
    let mut originals = Vec::new();
    for pe in 0..2 {
        let cpu = if pe == 0 {
            &mut machine.cpu
        } else {
            let Peer::Parked(peer) = &mut machine.peers[pe] else {
                panic!("parked PE")
            };
            &mut peer.cpu
        };
        cpu.state.x[3] = 0x1234 + pe as u64;
        cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        originals.push(cpu.state.clone());
    }
    machine.timers = Some(Some(100));
    machine.device_lines = Some((
        Lines {
            irq: true,
            fiq: false,
        },
        100,
        0,
    ));
    machine.mirrors[0] = stela_compiler::x86_64::register_read::Cell {
        readable: 1,
        value: 0x1234,
    };
    machine.prediction_context = None;
    let old_generation = machine.translation_generation;
    let old_regimes = machine.host.regimes.len();
    let mut events = Vec::new();
    let (devices, processors) = machine.processor_write_parts();
    devices
        .retained_write(
            processors,
            &[
                ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                },
                ProcessorChange {
                    domain: 2,
                    state: RETAINED_GATED,
                },
            ],
            false,
            &mut events,
        )
        .unwrap();
    assert_eq!(
        events,
        [
            "native preflight",
            "CPU and native dispatch settled",
            "native commit",
            "controller ACK"
        ]
    );
    assert_eq!(machine.cpu.state, originals[0]);
    assert_eq!(parked(&machine, 1).state, originals[1]);
    assert_eq!(machine.translation_generation, old_generation + 1);
    assert_eq!(machine.host.regimes.len(), old_regimes + 1);
    assert_eq!(machine.runnable(), 0);
    assert!(
        machine.devices.power.len() == 1,
        "no new reset/power notification"
    );
}

#[test]
fn refused_or_unused_synchronous_access_cannot_leave_a_partial_cpu_batch_or_ack() {
    for refusal in 0..3 {
        let mut machine = pair();
        machine
            .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
            .unwrap();
        machine.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        machine.slice_end = 123;
        let old_generation = machine.translation_generation;
        let old_regimes = machine.host.regimes.len();
        let mut events = Vec::new();
        let mut changes = vec![
            ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            },
            ProcessorChange {
                domain: 2,
                state: RETAINED_GATED,
            },
        ];
        if refusal == 1 {
            changes[1].domain = 999;
        }
        let (devices, processors) = machine.processor_write_parts();
        if refusal == 2 {
            let _unused = processors;
        } else {
            assert!(matches!(
                devices.retained_write(processors, &changes, refusal == 0, &mut events),
                Err(DeviceError::TransferRefused(_))
            ));
            assert_eq!(events, ["native preflight"]);
        }
        assert!(machine.cpu.monitor.is_some());
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.processors().paused(1), Some(false));
        assert_eq!(machine.slice_end, 123);
        assert_eq!(machine.translation_generation, old_generation);
        assert_eq!(machine.host.regimes.len(), old_regimes);
    }
}

#[test]
fn native_dispatch_preflight_failure_precedes_participant_clock_and_cpu_changes() {
    for field in [
        "translation generation",
        "translation changes",
        "prediction isolations",
    ] {
        let mut machine = pair();
        machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
        machine.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        machine.slice_end = 123;
        match field {
            "translation generation" => machine.translation_generation = u64::MAX,
            "translation changes" => machine.statistics.translation_changes = u64::MAX,
            _ => {
                machine.prediction_context = None;
                machine.statistics.prediction_isolations = u64::MAX;
            }
        }
        let before_generation = machine.translation_generation;
        let before_regimes = machine.host.regimes.len();
        let expected_clock = (machine.clock.last(), machine.clock.host_deadline(1_000));
        machine.host.now = 100;
        let result = machine.processor_write().apply(&[ProcessorChange {
            domain: 1,
            state: RETAINED_GATED,
        }]);
        assert!(
            matches!(result, Err(ProcessorPowerError::NativeStateExhausted(actual)) if actual == field)
        );
        assert!(machine.cpu.monitor.is_some());
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.slice_end, 123);
        assert_eq!(machine.translation_generation, before_generation);
        assert_eq!(machine.host.regimes.len(), before_regimes);
        assert_eq!(
            (machine.clock.last(), machine.clock.host_deadline(1_000)),
            expected_clock
        );
    }
}

#[test]
fn borrowed_native_settlement_matches_full_canonical_regime_invalidation() {
    fn populated() -> Machine<FakeHost, Board> {
        let mut machine = pair();
        machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
        machine.timers = Some(Some(100));
        machine.floating_point = Some(Some(1));
        let _ = machine.memory_checks();
        let _ = machine.native_system();
        let _ = machine.debug_mode();
        machine.mirrors[0] = stela_compiler::x86_64::register_read::Cell {
            readable: 1,
            value: 7,
        };
        machine.device_lines = Some((
            Lines {
                irq: true,
                fiq: true,
            },
            100,
            0,
        ));
        machine.watch.ranges[0] = (0x1000, 0x1fff);
        machine.watch.pass = [Some(0x1000), None];
        machine.tag_checks = [true, true];
        machine.prediction_context = None;
        machine.pointer.open(super::super::pointer::PointerInputs {
            keys: [Some([1, 2]); 5],
            version: crate::pauth::Version::Classic,
            tcr: 17,
        });
        assert!(machine.pointer.is_open());
        machine
    }
    let mut expected = populated();
    let mut actual = populated();
    expected.translations_changed();
    let _settled = actual
        .processor_write()
        .apply(&[ProcessorChange {
            domain: 1,
            state: RETAINED_GATED,
        }])
        .unwrap();
    assert!(actual.timers == expected.timers && actual.floating_point == expected.floating_point);
    assert!(
        actual.memory_checks == expected.memory_checks
            && actual.native_system == expected.native_system
    );
    assert!(actual.debug.is_none() && expected.debug.is_none());
    assert!(!actual.pointer.is_open() && !expected.pointer.is_open());
    assert_eq!(*actual.mirrors, *expected.mirrors);
    assert_eq!(actual.device_lines, expected.device_lines);
    assert_eq!(actual.watch, expected.watch);
    assert_eq!(actual.tag_checks, expected.tag_checks);
    assert!(actual.prediction_context == expected.prediction_context);
    assert_eq!(
        actual.translation_generation,
        expected.translation_generation
    );
    assert_eq!(
        actual.statistics.translation_changes,
        expected.statistics.translation_changes
    );
    assert_eq!(
        actual.statistics.prediction_isolations,
        expected.statistics.prediction_isolations
    );
    assert_eq!(actual.host.regimes, expected.host.regimes);
    assert_eq!(actual.host.isolations, expected.host.isolations);
    assert_eq!(
        actual.host.code_invalidations,
        expected.host.code_invalidations
    );
}

#[test]
fn paused_timer_events_and_timeouts_remain_pending_without_idle_skip_spinning() {
    let mut machine = pair();
    machine
        .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
        .unwrap();
    machine.cpu.registers.set(Register::CNTHP_CTL_EL2, 0, 1);
    machine.cpu.registers.set(Register::CNTHP_CVAL_EL2, 0, 10);
    machine.cpu.registers.set(Register::CNTKCTL_EL1, 0, 1 << 2);
    machine.event_sample = Some(0);
    machine.waiting = Some(Wait {
        kind: WaitKind::Event,
        timeout: Some(super::super::Timeout {
            limit: 7,
            offset: 0,
        }),
        down: false,
    });
    let Peer::Parked(other) = &mut machine.peers[1] else {
        panic!("PE1 parked")
    };
    other.cpu.registers.set(Register::CNTHP_CTL_EL2, 0, 1);
    other.cpu.registers.set(Register::CNTHP_CVAL_EL2, 0, 15);
    other.waiting = Some(Wait {
        kind: WaitKind::Interrupt,
        timeout: None,
        down: false,
    });
    let plan = machine
        .prepare_processor_power(&[
            ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            },
            ProcessorChange {
                domain: 2,
                state: RETAINED_GATED,
            },
        ])
        .unwrap();
    machine.settle_processor_power(plan).unwrap();
    machine.host.now = 20;
    machine.set_idle_skip(true).unwrap();
    assert_eq!(machine.next_deadline(20), None);
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    assert_eq!(
        machine.statistics.waits, 0,
        "expired paused deadlines are not wake sources"
    );
    assert_eq!(machine.cpu.read(Register::CNTHP_CVAL_EL2), 10);
    assert_eq!(machine.event_sample, Some(0), "event history is retained");
    power_change(&mut machine, 1, RETAINED_ACTIVE);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    assert_eq!(machine.cpu.pc, BASE + 4, "the original wait completes once");
    assert!(machine.waiting.is_none());
    assert!(machine.cpu.event && timer::asserted(&machine.cpu, 20));
}

#[test]
fn monitors_exclude_pause_time() {
    use crate::machine::{
        amu::Amu,
        pmu::{self, Context, Pmu},
    };
    let mut machine = board(&[], Board::default(), alloc::vec![identity(0)]);
    machine.cpu.retired = 10;
    let context = Context {
        el: 1,
        filter: pmu::Filter::Guest,
        waiting: false,
    };
    let seed = (1 << 63) | 10;
    let mut monitor = Pmu::new(36_000_000, 24_000_000);
    monitor.write(pmu::PMCR1, 1 << 16, 0, 10, context).unwrap();
    monitor
        .write(pmu::PMCR1_EL12, 1 << 16, 0, 10, context)
        .unwrap();
    monitor.write(pmu::PMC[0], seed, 0, 10, context).unwrap();
    monitor
        .write(pmu::PMCR0, 1 | 4 << 8 | 1 << 12, 0, 10, context)
        .unwrap();
    machine.cpu.pmu = Some(monitor);
    let mut amu = Amu::new(36_000_000, 24_000_000);
    amu.set_enables(7, true, 0, 10);
    machine.cpu.amu = Some(amu);
    machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
    machine.host.now = 1;
    power_change(&mut machine, 1, RETAINED_GATED);
    machine.host.now = 1000;
    machine.sync_monitor();
    let monitor = machine.cpu.pmu.as_mut().unwrap();
    assert_eq!(
        monitor
            .read(
                pmu::PMC[0],
                1000,
                10,
                Context {
                    waiting: true,
                    ..context
                }
            )
            .unwrap(),
        seed + 1
    );
    assert!(monitor.asserted(1000, 10), "pending PMI is retained");
    let amu = machine.cpu.amu.as_ref().unwrap();
    assert_eq!(
        (
            amu.count(0, 1000, 10),
            amu.count(1, 1000, 10),
            amu.count(2, 1000, 10)
        ),
        (1, 1, 0)
    );
    power_change(&mut machine, 1, RETAINED_ACTIVE);
    machine.host.now = 1001;
    let monitor = machine.cpu.pmu.as_mut().unwrap();
    assert_eq!(
        monitor.read(pmu::PMC[0], 1001, 10, context).unwrap(),
        seed + 3
    );
    let amu = machine.cpu.amu.as_ref().unwrap();
    assert_eq!(
        (
            amu.count(0, 1001, 10),
            amu.count(1, 1001, 10),
            amu.count(2, 1001, 10)
        ),
        (3, 2, 0)
    );
    assert_eq!(machine.cpu.retired, 10);
}

#[test]
fn a_start_cannot_bypass_a_kept_clock_blocker() {
    let mut machine = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
    let mut binding = core_binding(1, 1);
    binding.initial = RETAINED_GATED;
    machine.bind_processor_power(&[binding]).unwrap();
    machine
        .start(Start {
            cpu: 1,
            address: START,
        })
        .unwrap();
    assert!(!machine.ready(1, 0));
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    power_change(&mut machine, 1, RETAINED_ACTIVE);
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.pc), (1, START));
    assert_eq!(machine.devices.power, [(1, true)]);
}

/// Original J873GAP decoded ADT SHA-256
/// 3252a3f13dc025ffa8551c7a5da6a71501f76ea6c5d38aa35390f9268a6dc378:
/// CPU6/7 P and CPU8..11 M share physical cluster 1. Only these affinity
/// coordinates are checked: MIDR=0 is an explicit synthetic fixture,
/// and using a modeled cluster register does not admit that register or
/// any complete M6 hardware profile.
#[test]
fn original_m6_mixed_cluster_shares_live_or_parked_owners_in_either_start_order() {
    use super::super::tests::board_on;
    use {crate::machine::ctrr::Field, crate::machine::impdef, stela_contracts::Chip};
    const MPIDRS: [u64; 12] = [
        0x8000_0000,
        0x8000_0001,
        0x8000_0002,
        0x8000_0003,
        0x8000_0004,
        0x8000_0005,
        0x8001_0100,
        0x8001_0101,
        0x8004_0102,
        0x8004_0103,
        0x8004_0104,
        0x8004_0105,
    ];
    let counter = impdef::lookup(impdef::CLUSTER_COUNTER_C0, Chip::AppleM2).unwrap();
    for order in [[6, 7, 8, 9, 10, 11], [8, 9, 10, 11, 6, 7]] {
        for live in [false, true] {
            let identities = MPIDRS
                .into_iter()
                .map(|mpidr| Identity {
                    midr: 0,
                    mpidr,
                    clock: None,
                    caches: None,
                })
                .collect();
            let mut machine = board_on(Chip::AppleM6, &[], super::super::NoDevices, identities);
            let first = order[0];
            machine
                .start(Start {
                    cpu: first,
                    address: START,
                })
                .unwrap();
            let Peer::Parked(owner) = &mut machine.peers[first] else {
                panic!("the first owner is parked")
            };
            owner
                .cpu
                .ctrr
                .borrow_mut()
                .write(0, Field::Lower, BASE)
                .unwrap();
            owner
                .cpu
                .ctrr
                .borrow_mut()
                .write(0, Field::Lock, 1)
                .unwrap();
            owner.cpu.apple.impdef.write(counter, 17).unwrap();
            let shared = owner.cpu.ctrr.clone();
            if live {
                machine.switch_to(first);
            }
            for &pe in &order[1..] {
                machine
                    .start(Start {
                        cpu: pe,
                        address: START + pe as u64 * 4,
                    })
                    .unwrap();
                let Peer::Parked(target) = &mut machine.peers[pe] else {
                    panic!("a new PE is parked")
                };
                assert!(shared.ptr_eq(&target.cpu.ctrr));
                assert_eq!(target.cpu.ctrr.borrow().read(0, Field::Lower), BASE);
                assert!(
                    target
                        .cpu
                        .ctrr
                        .borrow_mut()
                        .write(0, Field::Lower, 0)
                        .is_err()
                );
                assert_eq!(target.cpu.apple.impdef.read(counter), Ok(17));
                target.cpu.apple.impdef.write(counter, 19).unwrap();
                if live {
                    assert_eq!(machine.cpu.apple.impdef.read(counter), Ok(19));
                    machine.cpu.apple.impdef.write(counter, 17).unwrap();
                } else {
                    let Peer::Parked(owner) = &mut machine.peers[first] else {
                        panic!("the original owner is parked")
                    };
                    assert_eq!(owner.cpu.apple.impdef.read(counter), Ok(19));
                    owner.cpu.apple.impdef.write(counter, 17).unwrap();
                }
            }
            // E cores are a different physical cluster even though all
            // P/M owners above now share one underlying register bank.
            machine
                .start(Start {
                    cpu: 1,
                    address: START,
                })
                .unwrap();
            let Peer::Parked(other) = &mut machine.peers[1] else {
                panic!("the E core is parked")
            };
            assert!(!shared.ptr_eq(&other.cpu.ctrr));
            assert_eq!(other.cpu.ctrr.borrow().read(0, Field::Lock), 0);
            assert_eq!(other.cpu.apple.impdef.read(counter), Ok(0));
        }
    }
}

#[test]
fn every_pe_and_new_cluster_starts_from_the_core_lock_handoff() {
    use super::super::tests::board_on;
    use stela_contracts::Chip;
    let identities = [0x8000_0000, 0x8001_0100]
        .into_iter()
        .map(|mpidr| Identity {
            midr: 0,
            mpidr,
            clock: None,
            caches: None,
        })
        .collect();
    let mut machine = board_on(Chip::AppleM5, &[], super::super::NoDevices, identities);
    let handoff = ctrr::CoreLocks {
        locked: alloc::vec![ctrr::Locked {
            region: ctrr::LockRegion::CtxrA,
            first: 0x100_070a_4000,
            last: 0x100_0710_bfff,
        }],
        legacy_locked: true,
        tag_offset: 0,
    };
    machine.hand_off_core_locks(handoff.clone());
    assert_eq!(
        *machine.cpu.ctrr.borrow(),
        ctrr::Cluster::handed_off(&handoff)
    );
    machine.cpu.ctrr_core.el2.windows[0].lower = 0x1000;
    machine
        .start(Start {
            cpu: 1,
            address: START,
        })
        .unwrap();
    let Peer::Parked(other) = &mut machine.peers[1] else {
        panic!("the other cluster's PE is parked")
    };
    assert!(!machine.cpu.ctrr.ptr_eq(&other.cpu.ctrr));
    assert_eq!(
        *other.cpu.ctrr.borrow(),
        ctrr::Cluster::handed_off(&handoff)
    );
    assert_eq!(other.cpu.ctrr_core, ctrr::Core::handed_off(&handoff));
}

#[test]
fn all_participants_preflight_and_settle_together() {
    use super::super::tests::board_on;
    let identities = (0..8)
        .map(|pe| Identity {
            midr: 0x611f_0320,
            mpidr: 0x8000_0000 | (pe / 4) << 16 | (pe / 4) << 8 | (pe % 4),
            clock: None,
            caches: None,
        })
        .collect();
    let mut machine = board_on(
        stela_contracts::Chip::AppleM2,
        &[],
        super::super::NoDevices,
        identities,
    );
    for pe in 1..8 {
        machine
            .start(Start {
                cpu: pe,
                address: START + pe as u64 * 4,
            })
            .unwrap();
        let Peer::Parked(other) = &mut machine.peers[pe] else {
            panic!("started PE parked")
        };
        other.cpu.state.x[5] = pe as u64;
    }
    let mut bindings: Vec<_> = (0..8).map(|pe| core_binding(pe as u64 + 1, pe)).collect();
    for (domain, members) in [(9, alloc::vec![0, 1, 2, 3]), (10, alloc::vec![4, 5, 6, 7])] {
        bindings.push(ProcessorBinding {
            domain,
            target: ProcessorTarget::Cluster { members },
            initial: RETAINED_ACTIVE,
        });
    }
    machine.bind_processor_power(&bindings).unwrap();
    assert_eq!(machine.processors().domain_count(), 10);
    assert_eq!(machine.runnable(), 8);
    let good = ProcessorChange {
        domain: 9,
        state: RETAINED_GATED,
    };
    assert!(
        machine
            .prepare_processor_power(&[
                good,
                ProcessorChange {
                    domain: 7,
                    state: stela_contracts::bus::LifecycleState {
                        reset: true,
                        ..RETAINED_ACTIVE
                    }
                }
            ])
            .is_err()
    );
    assert_eq!(machine.runnable(), 8);
    let plan = machine
        .prepare_processor_power(&[
            good,
            ProcessorChange {
                domain: 10,
                state: RETAINED_GATED,
            },
        ])
        .unwrap();
    machine.settle_processor_power(plan).unwrap();
    assert_eq!(machine.runnable(), 0);
    assert!((0..8).all(|pe| machine.processors().paused(pe) == Some(true)));
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    let plan = machine
        .prepare_processor_power(&[ProcessorChange {
            domain: 9,
            state: RETAINED_ACTIVE,
        }])
        .unwrap();
    machine.settle_processor_power(plan).unwrap();
    assert_eq!(machine.runnable(), 4);
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.state.x[5]), (1, 1));
    let plan = machine
        .prepare_processor_power(&[
            ProcessorChange {
                domain: 10,
                state: RETAINED_ACTIVE,
            },
            ProcessorChange {
                domain: 7,
                state: RETAINED_GATED,
            },
        ])
        .unwrap();
    machine.settle_processor_power(plan).unwrap();
    assert_eq!(machine.runnable(), 7);
    assert_eq!(machine.processors().paused(6), Some(true));
}

#[test]
fn device_pc_sample_observes_the_requested_live_peer_before_consumption() {
    #[derive(Default)]
    struct Capture {
        target: Option<usize>,
        observations: Vec<(u64, u64)>,
        reads: usize,
    }
    impl Devices for Capture {
        fn pc_sample_target(&self, _: u64, _: u8) -> Option<usize> {
            self.target
        }
        fn observe_pc_sample(&mut self, physical: u64, pc: u64) {
            self.observations.push((physical, pc));
        }
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            self.reads += 1;
            Ok(0)
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn lines(&mut self, _: usize, _: u64) -> crate::machine::Lines {
            crate::machine::Lines::default()
        }
    }
    let physical = 0x2_1004_0000;
    let mut machine = board(
        &[],
        Capture::default(),
        alloc::vec![identity(0), identity(1)],
    );
    let pc = BASE + 0x400;
    machine.peers[1] = Peer::Parked(Box::new(Parked {
        cpu: Cpu::of(machine.profile.chip, pc, Pstate::reset(2)),
        event_sample: None,
        waiting: None,
        mirrors: super::super::Mirrors::default(),
    }));
    assert_eq!(machine.device_read(physical, 4, 0), Ok(0));
    assert_eq!(machine.devices.reads, 1);
    assert!(machine.devices.observations.is_empty());
    machine.devices.target = Some(1);
    assert_eq!(machine.device_read(physical, 4, 0), Ok(0));
    assert_eq!(machine.devices.observations, [(physical, pc)]);
    if let Peer::Parked(parked) = &mut machine.peers[1] {
        parked.cpu.pc += 4;
    }
    assert_eq!(machine.device_read(physical, 4, 0), Ok(0));
    assert_eq!(
        machine.devices.observations,
        [(physical, pc), (physical, pc + 4)]
    );
    assert_eq!(machine.devices.reads, 3);
    machine.peers[1] = Peer::Off;
    assert!(machine.device_read(physical, 4, 0).is_err());
    assert_eq!(
        machine.devices.reads, 3,
        "missing peer refuses before consuming the device read"
    );
    assert_eq!(machine.devices.observations.len(), 2);
}

#[test]
fn single_pe_parallel_waits_match_serial() {
    struct NoKick;
    impl super::super::parallel::Kick for NoKick {
        fn kick(&self, _: usize) {}
    }
    for (pes, host_wake, expected) in [
        (1, false, Stop::Idle),
        (1, true, Stop::Waiting),
        (2, false, Stop::Waiting),
        (2, true, Stop::Waiting),
    ] {
        let devices = Board {
            host_wake,
            ..Board::default()
        };
        let identities = (0..pes).map(|pe| identity(pe as u64)).collect();
        let mut machine = board(&[], devices, identities);
        let hub = super::super::parallel::Hub::new(pes, NoKick);
        machine.enter_parallel(hub).unwrap();
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.schedule(), Err(expected));
    }
}

#[test]
fn a_wait_only_the_host_can_end_that_reaches_the_limit_or_owes_the_host_returns_to_it() {
    let mut machine = board(&[], Board::default(), alloc::vec![identity(0)]);
    machine.system_instruction(WFI).unwrap();
    // Nothing can wake the PE: idle.
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    // Only the host's inputs can: without a limit, back to the host at
    // once, waiting on nothing.
    machine.devices.host_wake = true;
    assert_eq!(machine.schedule(), Err(Stop::Waiting));
    assert_eq!(machine.host.now, 0);
    // With a limit, after waiting that long (the fake host's waits last
    // 1000 ticks), and idle skip has no deadline to leap to.
    machine.set_wait_limit(Some(2500));
    machine.set_idle_skip(true).unwrap();
    assert_eq!(machine.schedule(), Err(Stop::Waiting));
    assert_eq!(machine.host.now, 3000);
    // The limit bounds the run's waits in all: a later one in the same
    // run returns at once.
    machine.set_idle_skip(false).unwrap();
    machine.devices.host_wake = false;
    machine.devices.dma = Some(10_000);
    assert_eq!(machine.schedule(), Err(Stop::Waiting));
    assert_eq!(machine.host.now, 3000);
    // It bounds a wait for a deadline too, in the next run; the deadline
    // still ends the wait it falls in.
    machine.waited = 0;
    assert_eq!(machine.schedule(), Err(Stop::Waiting));
    assert_eq!(machine.host.now, 6000);
    // A device that moved bytes for the host returns to it before any
    // wait, once.
    machine.waited = 0;
    machine.devices.host_service = true;
    assert_eq!(machine.schedule(), Err(Stop::Waiting));
    assert_eq!(machine.host.now, 6000);
    assert!(!machine.devices.host_service);
    machine.set_wait_limit(None);
    machine.schedule().unwrap();
    assert!(machine.host.now >= 10_000);
    assert_eq!(machine.processor(), 0);
}

#[test]
fn a_started_pe_leaves_reset_at_its_address_in_el2_with_its_own_identity() {
    let mut machine = pair();
    // PE 0 keeps its time slice; PE 1 waits for its turn.
    assert_eq!(machine.processor(), 0);
    assert_eq!(machine.cpu.read(Register::MPIDR_EL1), 0x8000_0000);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert_eq!(machine.statistics.switches, 1);
    let cpu = &machine.cpu;
    assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.sp), (START, 2, true));
    assert_eq!(cpu.pstate.daif, DAIF_ALL);
    assert_eq!(cpu.read(Register::MIDR_EL1), 0x611f_0330);
    assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0100);
    assert_eq!(cpu.read(Register::VMPIDR_EL2), 0x8000_0100);
    // FP/SIMD is not trapped out of reset.
    assert_eq!(cpu.read(Register::CPTR_EL2) >> 20 & 0b11, 0b11);
    assert_eq!(parked(&machine, 0).pc, BASE);
    // Round robin returns to PE 0.
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE));
    // A PE that is not held in reset, or that the profile does not have,
    // cannot be started.
    for cpu in [1, 2] {
        machine.devices.starts.push(Start {
            cpu,
            address: START,
        });
        assert!(matches!(machine.schedule(), Err(Stop::Unsupported(_))));
    }
}

#[test]
fn an_rmr_el2_reset_request_warm_resets_the_pe_at_its_reset_vector() {
    const MSR_RMR_EL2_X1: u32 = 0xd51c_c041;
    const MRS_X1_RMR_EL2: u32 = 0xd53c_c041;
    let devices = Board {
        reset: Some(START),
        ..Board::default()
    };
    let mut machine = board(&[], devices, alloc::vec![identity(0)]);
    let cpu = &mut machine.cpu;
    cpu.set_pstate(Pstate::reset(2));
    cpu.registers.set_raw(Register::OSLSR_EL1, 0, 0);
    cpu.registers.set(Register::DBGBVR_EL1, 1, 0x1000);
    cpu.registers.set(Register::ELR_EL2, 0, 0x8000);
    cpu.claim = 0b101;
    cpu.state.x[5] = 7;
    cpu.monitor = Some(Reservation {
        granule: BASE,
        bytes: [0; RESERVATION_GRANULE as usize],
    });
    // RR clear requests nothing.
    machine.cpu.state.x[1] = 0b01;
    machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    machine.cpu.state.x[1] = 0b10;
    machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
    let cpu = &machine.cpu;
    assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.sp), (START, 2, true));
    assert_eq!(cpu.pstate.daif, DAIF_ALL);
    assert_eq!((cpu.state.x[5], cpu.monitor), (0, None));
    assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0000);
    // Only a Cold reset sets the OS lock, the breakpoints and the claim
    // tags; ELR_EL2 is UNKNOWN (0 here) and RR clears.
    assert_eq!(cpu.read(Register::OSLSR_EL1), 0);
    assert_eq!(cpu.registers.get(Register::DBGBVR_EL1, 1), 0x1000);
    assert_eq!(cpu.claim, 0b101);
    assert_eq!(cpu.read(Register::ELR_EL2), 0);
    machine.system_instruction(MRS_X1_RMR_EL2).unwrap();
    assert_eq!(machine.cpu.state.x[1], 1);
    // EL1 cannot reach RMR_EL2, and a board without a reset vector
    // cannot reset the PE: the request is reported once and the PE runs on.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
    assert_eq!(machine.cpu.read(Register::ESR_EL1), 0x0200_0000);
    machine.devices.reset = None;
    machine.cpu.set_pstate(Pstate::reset(2));
    machine.cpu.state.x[1] = 0b10;
    let pc = machine.cpu.pc;
    machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (pc + 4, 2));
    assert_eq!(machine.take_unmodeled().len(), 1);
}

#[test]
fn a_slice_ends_after_its_blocks_or_its_counter_time() {
    let mut machine = pair();
    let quantum = machine.profile.counter_frequency / QUANTUM_HZ;
    // PE 0's blocks spent, PE 1 runs its slice.
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    // Within both bounds PE 1 keeps running.
    machine.host.now += quantum - 1;
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    // Its counter time spent, PE 0 runs, though blocks remain.
    machine.host.now += 1;
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
}

#[test]
fn wfe_parks_until_an_event_and_writes_clear_other_pes_monitors() {
    let mut machine = pair();
    // PE 0 waits with no event: PE 1 runs.
    machine.system_instruction(WFE).unwrap();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert!(!parked(&machine, 0).event);
    // SEVL is local: PE 0 stays parked when PE 1's slice ends.
    machine.system_instruction(SEVL).unwrap();
    assert!(machine.cpu.event && !parked(&machine, 0).event);
    machine.system_instruction(WFE).unwrap();
    assert!(!machine.cpu.event);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    // SEV reaches PE 0, whose WFE completes and consumes the event.
    machine.system_instruction(SEV).unwrap();
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 4, false));
    // A WFE that completes at once yields the rest of the slice to PE 1,
    // and PE 0 continues after it at PE 1's next WFE.
    machine.system_instruction(SEVL).unwrap();
    machine.system_instruction(WFE).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 12);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    machine.system_instruction(SEVL).unwrap();
    machine.system_instruction(WFE).unwrap();
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE + 12));
    // PE 0 waits in WFE behind a load exclusive. PE 1 running clears
    // nothing until it writes the granule; then PE 0's monitor clears,
    // which generates the event that wakes it.
    let data = 0x400;
    machine.cpu.monitor = Some(Reservation {
        granule: BASE + data as u64,
        bytes: [0; RESERVATION_GRANULE as usize],
    });
    machine.system_instruction(WFE).unwrap();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert!(parked(&machine, 0).monitor.is_some() && !parked(&machine, 0).event);
    machine.host.ram[data + 8] = 1;
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    assert_eq!(machine.cpu.monitor, None);
    assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 16, false));
    // PE 1 may have written the granule and restored its bytes: PE 0,
    // preempted behind a load exclusive, resumes without its
    // reservation, and without an event since no change shows.
    let mut bytes = [0; RESERVATION_GRANULE as usize];
    bytes.copy_from_slice(&machine.host.ram[data..data + RESERVATION_GRANULE as usize]);
    machine.cpu.monitor = Some(Reservation {
        granule: BASE + data as u64,
        bytes,
    });
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 0);
    assert_eq!((machine.cpu.monitor, machine.cpu.event), (None, false));
}

#[test]
fn wfi_parks_until_its_own_pes_lines_and_idles_when_nothing_can_wake() {
    let mut machine = pair();
    machine.system_instruction(WFI).unwrap();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    // PE 1's IRQ does not wake PE 0. The board's lines change as a
    // device access the engine is told of would change them.
    machine.devices.irq = [false, true];
    machine.device_lines = None;
    end_slice(&mut machine);
    machine.devices.lines_asked.clear();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert_eq!(machine.devices.lines_asked, [0]);
    // Its own line does, masked or not, and WFI completes.
    machine.devices.irq = [true, false];
    machine.device_lines = None;
    end_slice(&mut machine);
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE + 4));
    assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
    // With both PEs in WFI and no timer, stream or device deadline, the
    // machine is idle.
    machine.devices.irq = [false, false];
    machine.device_lines = None;
    machine.system_instruction(WFI).unwrap();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    machine.system_instruction(WFI).unwrap();
    assert_eq!(machine.schedule(), Err(Stop::Idle));
}
#[test]
fn dma_dispatch_reads_one_clock_only_when_pending_and_publishes_when_due() {
    let mut machine = board(&[], Board::default(), Vec::new());
    let reads = machine.host.counter_reads;
    machine.poll_due_devices().unwrap();
    assert_eq!(machine.host.counter_reads, reads);
    machine.devices.dma = Some(100);
    machine.host.now = 99;
    machine.poll_due_devices().unwrap();
    assert_eq!(machine.host.counter_reads, reads + 1);
    assert_eq!(machine.devices.dma, Some(100));
    assert_eq!(&machine.host.ram[0x100..0x103], &[0; 3]);
    machine.host.now = 100;
    machine.poll_due_devices().unwrap();
    assert_eq!(machine.host.counter_reads, reads + 2);
    assert_eq!(machine.devices.dma, None);
    assert_eq!(&machine.host.ram[0x100..0x103], b"USB");
    assert!(machine.devices.irq[0]);
    assert!(machine.device_lines.is_none());
    machine.poll_due_devices().unwrap();
    assert_eq!(machine.host.counter_reads, reads + 2);
}

#[test]
fn native_bus_peer_dma_runs_and_wakes_a_waiting_pe_without_mmio() {
    struct NoKick;
    impl super::super::parallel::Kick for NoKick {
        fn kick(&self, _: usize) {}
    }
    for parallel in [true, false] {
        let devices = Board {
            dma: Some(1000),
            ..Board::default()
        };
        let identities = if parallel {
            alloc::vec![identity(0), identity(1)]
        } else {
            Vec::new()
        };
        let mut machine = board(&[WFI], devices, identities);
        if parallel {
            let hub = super::super::parallel::Hub::new(2, NoKick);
            machine.enter_parallel(hub).unwrap();
        }
        assert_eq!(machine.devices.deadline(machine.host.now), None);
        machine.waiting = Some(Wait {
            kind: WaitKind::Interrupt,
            timeout: None,
            down: false,
        });
        machine.schedule().unwrap();
        assert!(machine.waiting.is_none());
        assert!(machine.host.now >= 1000);
        let mut bytes = [0; 3];
        assert!(machine.host.read_ram(BASE + 0x100, &mut bytes));
        assert_eq!(&bytes, b"USB");
        assert!(machine.devices.irq[0]);
        assert_eq!(machine.devices.dma_deadline(), None);
    }
}

#[test]
fn a_wait_pass_never_gives_the_devices_an_earlier_count() {
    let devices = Board {
        dma: Some(1000),
        ..Board::default()
    };
    let mut machine = board(&[WFI], devices, Vec::new());
    // The host counter moves on at every read, as a real one does.
    machine.host.counter_step = 7;
    machine.waiting = Some(Wait {
        kind: WaitKind::Interrupt,
        timeout: None,
        down: false,
    });
    machine.schedule().unwrap();
    assert!(machine.waiting.is_none());
    let counts = &machine.devices.counts;
    assert!(counts.len() > 2, "{counts:?}");
    assert!(counts.is_sorted(), "{counts:?}");
}

#[test]
fn a_switch_keeps_the_device_lines_and_reads_the_incoming_pes_pins() {
    let mut machine = pair();
    machine.devices.pins = true;
    machine.devices.dma = Some(u64::MAX - 1);
    machine.devices.irq = [false, true];
    machine.device_lines = None;
    let current = machine.processor();
    let other = current ^ 1;
    assert_eq!(machine.lines().irq, machine.devices.irq[current]);
    let asked = machine.devices.lines_asked.len();
    machine.switch_to(other);
    // No device advances for the incoming PE: its latched pins answer.
    assert_eq!(machine.lines().irq, machine.devices.irq[other]);
    assert_eq!(machine.devices.lines_asked.len(), asked);
    assert_eq!(machine.devices.pins_asked, [other]);
    assert_eq!(machine.lines().irq, machine.devices.irq[other]);
    assert_eq!(machine.devices.pins_asked, [other]);
    // A board without latched pins is asked to advance again.
    machine.devices.pins = false;
    machine.switch_to(current);
    assert_eq!(machine.lines().irq, machine.devices.irq[current]);
    assert_eq!(machine.devices.lines_asked.len(), asked + 1);
}

#[test]
fn a_pe_takes_its_open_mirrored_reads_back_when_it_runs_again() {
    const MRS_X8_TPIDR_EL1: u32 = 0xd538_d088;
    let mut machine = pair();
    let current = machine.processor();
    let other = current ^ 1;
    machine.cpu.registers.set(Register::TPIDR_EL1, 0, 0x7000);
    machine.system_instruction(MRS_X8_TPIDR_EL1).unwrap();
    let open = machine.mirrors[0];
    assert_eq!((open.readable, open.value), (1, 0x7000));
    // The other PE's cells are its own, closed until it reads.
    machine.switch_to(other);
    assert_eq!(machine.mirrors[0].readable, 0);
    machine.switch_to(current);
    assert_eq!(machine.mirrors[0], open);
    // A change to a parked PE closes the cells it left.
    machine.switch_to(other);
    if let Peer::Parked(parked) = &mut machine.peers[current] {
        parked
            .cpu_mut()
            .registers
            .set(Register::TPIDR_EL1, 0, 0x8000);
    }
    machine.switch_to(current);
    assert_eq!(machine.mirrors[0].readable, 0);
}

/// Switch to the next PE that can run, which must be `pe`.
fn turn(machine: &mut Machine<FakeHost, Board>, pe: usize) {
    end_slice(machine);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), pe);
}

#[test]
fn a_store_exclusive_fails_once_another_pe_wrote_the_granule_and_its_retry_counts_both() {
    const LDXR_X1_X2: u32 = 0xc85f_7c41;
    const STXR_W3_X4_X2: u32 = 0xc803_7c44;
    let data = 0x400;
    let mut machine = pair();
    let value = |machine: &Machine<FakeHost, Board>| {
        u64::from_le_bytes(machine.host.ram[data..data + 8].try_into().unwrap())
    };
    let load = |machine: &mut Machine<FakeHost, Board>| {
        machine.cpu.state.x[2] = BASE + data as u64;
        machine.system_instruction(LDXR_X1_X2).unwrap();
        machine.cpu.state.x[1]
    };
    let store = |machine: &mut Machine<FakeHost, Board>, value| {
        machine.cpu.state.x[4] = value;
        machine.system_instruction(STXR_W3_X4_X2).unwrap();
        machine.cpu.state.x[3]
    };
    // Two PEs increment one counter with LDXR/STXR loops. PE 0 loads 0
    // and is preempted before its store; PE 1's whole increment passes.
    assert_eq!(load(&mut machine), 0);
    turn(&mut machine, 1);
    let seen = load(&mut machine);
    assert_eq!((seen, store(&mut machine, seen + 1)), (0, 0));
    // PE 0's store fails without writing; its retry loads PE 1's value
    // and passes, so neither increment is lost.
    turn(&mut machine, 0);
    assert_eq!((store(&mut machine, 1), value(&machine)), (1, 1));
    let seen = load(&mut machine);
    assert_eq!((seen, store(&mut machine, seen + 1)), (1, 0));
    assert_eq!(value(&machine), 2);
    // An LSE atomic (LDADD) runs natively and writes RAM directly: PE 1's
    // clears PE 0's reservation too, and PE 0's store fails.
    assert_eq!(load(&mut machine), 2);
    turn(&mut machine, 1);
    machine.host.ram[data..data + 8].copy_from_slice(&3u64.to_le_bytes());
    turn(&mut machine, 0);
    assert_eq!(machine.cpu.monitor, None);
    assert_eq!((store(&mut machine, 3), value(&machine)), (1, 3));
}

const LEVEL1: usize = 0xf000;
const LEVEL2: usize = 0xe000;
const LEVEL3: usize = 0xd000;

/// Write `value` to entry `index` of the translation table at `table`.
fn descriptor(machine: &mut Machine<FakeHost, Board>, table: usize, index: usize, value: u64) {
    let at = table + index * 8;
    machine.host.ram[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// The level 3 page descriptor of the test RAM page at `output`.
fn page(output: u64) -> u64 {
    const AF_INNER_SHAREABLE_PAGE: u64 = 1 << 10 | 3 << 8 | 0b11;
    output | AF_INNER_SHAREABLE_PAGE
}

/// Stage 1 of the running PE's EL1&0 regime with 4 KiB pages: VA = PA
/// for the test RAM's 16 pages.
fn map_pages(machine: &mut Machine<FakeHost, Board>) {
    const TABLE: u64 = 0b11;
    const TCR: u64 = 25 | 1 << 8 | 1 << 10 | 3 << 12 | 1 << 23 | 5 << 32;
    const SCTLR_M_C: u64 = 1 | 1 << 2;
    descriptor(
        machine,
        LEVEL1,
        (BASE >> 30) as usize,
        (BASE + LEVEL2 as u64) | TABLE,
    );
    descriptor(machine, LEVEL2, 0, (BASE + LEVEL3 as u64) | TABLE);
    for index in 0..16 {
        descriptor(machine, LEVEL3, index, page(BASE + index as u64 * 0x1000));
    }
    let registers = &mut machine.cpu.registers;
    registers.set(Register::TTBR0_EL1, 0, BASE + LEVEL1 as u64);
    registers.set(Register::TCR_EL1, 0, TCR);
    registers.set(Register::MAIR_EL1, 0, 0xff);
    let sctlr = registers.get(Register::SCTLR_EL1, 0) | SCTLR_M_C;
    registers.set(Register::SCTLR_EL1, 0, sctlr);
    machine.translations_changed();
}

#[test]
fn a_tlbi_broadcast_by_one_pe_reaches_the_cached_fetch_translations_of_every_pe() {
    const TLBI_VAE1IS_X0: u32 = 0xd508_8320;
    let code = BASE + 0x1000;
    let mut machine = pair();
    let fetch = |machine: &mut Machine<FakeHost, Board>| machine.fetch_physical(code).ok();
    // Both PEs run EL1 code through the same tables.
    map_pages(&mut machine);
    assert_eq!(fetch(&mut machine), Some(code));
    turn(&mut machine, 1);
    machine.cpu.pstate = Pstate::reset(1);
    map_pages(&mut machine);
    assert_eq!(fetch(&mut machine), Some(code));
    // PE 1 remaps the page. Its cached translation stands until it
    // invalidates the VA, as a TLB entry may.
    descriptor(&mut machine, LEVEL3, 1, page(BASE + 0x2000));
    assert_eq!(fetch(&mut machine), Some(code));
    machine.cpu.state.x[0] = code >> 12;
    machine.system_instruction(TLBI_VAE1IS_X0).unwrap();
    assert_eq!(fetch(&mut machine), Some(BASE + 0x2000));
    // The Inner Shareable invalidation reached PE 0, whose earlier
    // translation of the page is gone too.
    turn(&mut machine, 0);
    assert_eq!(fetch(&mut machine), Some(BASE + 0x2000));
}

#[test]
fn ic_ivau_by_one_pe_makes_every_pe_compile_the_new_code() {
    const RET: u32 = 0xd65f_03c0;
    const ADD_X0: u32 = 0x9100_0400;
    const IC_IVAU_X0: u32 = 0xd50b_7520;
    let code = 0x1000;
    for retained_pause in [false, true] {
        let mut machine = pair();
        machine.host.ram[code..code + 4].copy_from_slice(&RET.to_le_bytes());
        let compiled = |machine: &mut Machine<FakeHost, Board>| {
            let Ok(super::super::Fetched::Block(index)) =
                machine.fetch_block(BASE + code as u64, false)
            else {
                panic!("no block at the code");
            };
            (
                machine.blocks[index].source_hash,
                machine.statistics.compiled,
            )
        };
        let (old, count) = compiled(&mut machine);
        // PE 1, in the same regime, runs the shared compiled block.
        if retained_pause {
            machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
            power_change(&mut machine, 1, RETAINED_GATED);
            machine.schedule().unwrap();
            assert_eq!(machine.processor(), 1);
        } else {
            turn(&mut machine, 1);
        }
        machine.cpu.pstate = Pstate::reset(1);
        assert_eq!(compiled(&mut machine), (old, count));
        // It rewrites the code: until it invalidates the instruction cache
        // to the PoU the old block may still run, as stale instructions may.
        machine.host.ram[code..code + 8]
            .copy_from_slice(&[ADD_X0.to_le_bytes(), RET.to_le_bytes()].concat());
        assert_eq!(compiled(&mut machine), (old, count));
        machine.cpu.state.x[0] = BASE + code as u64;
        machine.system_instruction(IC_IVAU_X0).unwrap();
        // The host hears of it for PEs it runs in machines of their own.
        assert_eq!(machine.host.code_invalidations, [Some(BASE + code as u64)]);
        // The invalidation is broadcast: PE 0 compiles the new code.
        if retained_pause {
            power_change(&mut machine, 1, RETAINED_ACTIVE);
            machine.schedule().unwrap();
            assert_eq!(machine.processor(), 0);
        } else {
            turn(&mut machine, 0);
        }
        let (new, recompiled) = compiled(&mut machine);
        assert_ne!(new, old);
        assert_eq!(recompiled, count + 1);
    }
}

#[test]
fn interrupt_preempts_where_the_pe_stopped() {
    const MSR_DAIFCLR_I: u32 = 0xd503_42ff;
    const IRQ_CURRENT_SPX: u64 = 0x280;
    const HCR_TGE: u64 = 1 << 27;
    let mut machine = pair();
    machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
    // PE 1's line does not interrupt PE 0, unmasked.
    machine.devices.irq = [false, true];
    machine.cpu.pstate.daif = 0;
    assert!(!machine.deliver_interrupts());
    // PE 1 runs in the host, at EL2 with every interrupt masked from
    // reset: its IRQ stays pending until it clears PSTATE.I.
    turn(&mut machine, 1);
    let hcr = machine.cpu.read(Register::HCR_EL2) | HCR_TGE;
    machine.cpu.registers.set(Register::HCR_EL2, 0, hcr);
    machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
    assert!(!machine.deliver_interrupts());
    machine.system_instruction(MSR_DAIFCLR_I).unwrap();
    assert!(machine.deliver_interrupts());
    assert_eq!(
        (machine.cpu.pstate.el, machine.cpu.pc),
        (2, 0x4_0000 + IRQ_CURRENT_SPX)
    );
    assert_eq!(machine.cpu.read(Register::ELR_EL2), START + 4);
    assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
    // PE 0's line rises while it is preempted; it takes the IRQ when it
    // runs again, returning to where its slice ended.
    machine.devices.irq = [true, false];
    turn(&mut machine, 0);
    assert!(machine.deliver_interrupts());
    assert_eq!(
        (machine.cpu.pstate.el, machine.cpu.pc),
        (1, 0x1_0000 + IRQ_CURRENT_SPX)
    );
    assert_eq!(machine.cpu.read(Register::ELR_EL1), BASE);
}

#[test]
fn a_powered_down_pe_loses_its_state_and_leaves_reset_on_a_wake_line_or_a_start() {
    const MSR_CYC_OVRD_X0: u32 = 0xd51d_f500;
    const POWER_DOWN: u64 = 3 << 24;
    const LINES_DISABLED: u64 = 2 << 22 | 2 << 20;
    const RESET: u64 = BASE + 0xc00;
    let mut machine = pair();
    machine.devices.reset = Some(RESET);
    assert_eq!(machine.devices.power, [(1, true)]);
    // PE 0 powers down with its lines enabled; PE 1 runs, and its SEV
    // does not reach PE 0.
    machine.cpu.state.x[0] = POWER_DOWN;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.cpu.state.x[5] = 0x1234;
    machine.system_instruction(WFI).unwrap();
    assert_eq!(machine.devices.power, [(1, true), (0, false)]);
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    assert!(matches!(machine.peer_states()[0], PeerState::Down));
    machine.system_instruction(SEV).unwrap();
    // Its device line wakes it at its reset vector, its state lost.
    machine.devices.irq = [true, false];
    turn(&mut machine, 0);
    let cpu = &machine.cpu;
    assert_eq!(
        (cpu.pc, cpu.pstate.el, cpu.state.x[5], cpu.event),
        (RESET, 2, 0, false)
    );
    assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0000);
    assert_eq!(machine.devices.power.last(), Some(&(0, true)));
    // With both its lines disabled the asserted line does not wake it,
    // and with PE 1 waiting too the machine is idle until a device
    // starts PE 0 again.
    machine.cpu.state.x[0] = POWER_DOWN | LINES_DISABLED;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.system_instruction(WFI).unwrap();
    machine.schedule().unwrap();
    assert_eq!(machine.processor(), 1);
    machine.system_instruction(WFI).unwrap();
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    machine.devices.starts.push(Start {
        cpu: 0,
        address: START,
    });
    machine.schedule().unwrap();
    assert_eq!((machine.processor(), machine.cpu.pc), (0, START));
    // A board that holds no reset vector cannot wake it.
    machine.devices.reset = None;
    machine.devices.irq = [false, false];
    machine.cpu.state.x[0] = POWER_DOWN;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.system_instruction(WFI).unwrap();
    assert_eq!(machine.schedule(), Err(Stop::Idle));
    machine.devices.irq = [true, false];
    assert!(matches!(machine.schedule(), Err(Stop::Unsupported(_))));
}
