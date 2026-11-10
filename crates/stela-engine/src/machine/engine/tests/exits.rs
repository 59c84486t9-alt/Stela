//! Host timing of the engine's most frequent System exits: SVC from EL0 and
//! the ERET back, and the GENTER/GEXIT pair, through the same completion as
//! a native System exit (`Machine::completing` and
//! `complete_system_instruction`), followed by the variant the next fetch
//! derives. The manual test prints nanoseconds per transition; the others
//! check that the repeated transitions keep their architectural results.

use super::super::guarded::tests::gxf;
use super::*;
use crate::machine::exception::{DAIF_ALL, Pstate};

const SVC: u32 = 0xd400_0001;
const ERET: u32 = 0xd69f_03e0;
const GENTER: u32 = 0x0020_1420;
const GEXIT: u32 = 0x0020_1400;
const USER: u64 = BASE + 0x4000;
const VECTORS: u64 = BASE + 0x8000;
/// The lower-EL AArch64 synchronous vector.
const LOWER_SYNCHRONOUS: u64 = 0x400;
const HCR_E2H_TGE: u64 = 1 << 34 | 1 << 27;

/// One timed piece of work on a machine.
type Round = fn(&mut Machine<FakeHost, NoDevices>);

/// Complete `word` at the PC as a native System exit does.
fn exit(machine: &mut Machine<FakeHost, NoDevices>, word: u32) {
    let pc = machine.cpu.pc;
    let operation = machine.decode_system_operation(word);
    machine
        .completing(pc, |machine| {
            machine.complete_system_instruction(word, operation)
        })
        .unwrap();
}

/// A machine at EL0 with stage 1 on, whose SVCs go to EL1, or with `host`
/// to EL2 under HCR_EL2.{E2H,TGE}.
fn user(host: bool) -> Machine<FakeHost, NoDevices> {
    user_on(crate::machine::test_chip(), host)
}

/// [`user`] on `chip`.
fn user_on(chip: stela_contracts::Chip, host: bool) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine_on(chip, &[]);
    normal_memory(&mut machine, true);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::VBAR_EL1, 0, VECTORS);
    registers.set(SystemRegister::VBAR_EL2, 0, VECTORS);
    if host {
        registers.set(SystemRegister::HCR_EL2, 0, HCR_E2H_TGE);
    }
    machine.cpu.set_pstate(Pstate {
        sp: false,
        daif: 0,
        ..Pstate::reset(0)
    });
    machine.sync_regime();
    machine.cpu.pc = USER;
    machine
}

/// One SVC and its ERET, each with the next fetch's variant.
fn system_call(machine: &mut Machine<FakeHost, NoDevices>) {
    machine.cpu.pc = USER;
    exit(machine, SVC);
    machine.current_variant(false, false);
    exit(machine, ERET);
    machine.current_variant(false, false);
    machine.host.events.clear();
    machine.host.regimes.clear();
}

/// One GENTER and its GEXIT at EL1, each with the next fetch's variant.
fn guarded_call(machine: &mut Machine<FakeHost, NoDevices>, at: u64) {
    machine.cpu.pc = at;
    exit(machine, GENTER);
    machine.current_variant(false, false);
    exit(machine, GEXIT);
    machine.current_variant(false, false);
    machine.host.events.clear();
    machine.host.regimes.clear();
}

#[test]
fn repeated_system_calls_enter_and_return_exactly() {
    for host in [false, true] {
        let target = if host { 2 } else { 1 };
        let mut machine = user(host);
        for round in 0..4u64 {
            machine.cpu.pc = USER;
            machine.cpu.state.nzcv = 0x6000_0000;
            let retired = machine.cpu.retired;
            exit(&mut machine, SVC);
            assert_eq!(machine.cpu.pstate.el, target, "{host} {round}");
            assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
            assert_eq!(machine.cpu.pc, VECTORS + LOWER_SYNCHRONOUS);
            assert_eq!(machine.cpu.retired, retired + 1);
            let (elr, spsr, esr) = if host {
                (
                    SystemRegister::ELR_EL2,
                    SystemRegister::SPSR_EL2,
                    SystemRegister::ESR_EL2,
                )
            } else {
                (
                    SystemRegister::ELR_EL1,
                    SystemRegister::SPSR_EL1,
                    SystemRegister::ESR_EL1,
                )
            };
            assert_eq!(machine.cpu.read(elr), USER + 4);
            assert_eq!(machine.cpu.read(spsr), 0x6000_0000);
            assert_eq!(machine.cpu.read(esr), 0x5600_0000);
            let entered = machine.current_variant(false, false);
            exit(&mut machine, ERET);
            assert_eq!(machine.cpu.pstate.el, 0);
            assert_eq!(machine.cpu.pstate.daif, 0);
            assert_eq!(machine.cpu.pc, USER + 4);
            let returned = machine.current_variant(false, false);
            // EL0 checks SP alignment with SA0, EL1 and EL2 with SA.
            let sctlr = machine.cpu.regime_sctlr();
            assert_eq!(returned.checks.stack_alignment, sctlr & 1 << 4 != 0);
            machine.cpu.pc = USER;
            exit(&mut machine, SVC);
            assert_eq!(machine.current_variant(false, false), entered);
            exit(&mut machine, ERET);
            assert_eq!(machine.current_variant(false, false), returned);
        }
    }
}

/// Nanoseconds per transition of `round`, which makes `transitions` of
/// them, the best of several runs.
fn time(
    machine: &mut Machine<FakeHost, NoDevices>,
    transitions: u64,
    mut round: impl FnMut(&mut Machine<FakeHost, NoDevices>),
) -> u64 {
    const ROUNDS: u64 = 20_000;
    for _ in 0..ROUNDS / 10 {
        round(machine);
    }
    (0..5)
        .map(|_| {
            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                round(machine);
            }
            started.elapsed().as_nanos() as u64 / (ROUNDS * transitions)
        })
        .min()
        .unwrap()
}

/// `cargo test -p stela-engine --release --lib exit_transition_costs --
/// --ignored --nocapture`
#[test]
#[ignore = "manual: opt-in timing"]
fn exit_transition_costs() {
    for host in [false, true] {
        let mut machine = user(host);
        let ns = time(&mut machine, 2, system_call);
        std::println!("EXITS svc+eret host={host} ns_per_transition={ns}");
    }
    let mut machine = gxf(stela_contracts::Chip::AppleM2);
    let at = machine.cpu.pc;
    let ns = time(&mut machine, 2, |machine| guarded_call(machine, at));
    std::println!("EXITS genter+gexit ns_per_transition={ns}");
    // Four PEs of one M2 cluster at once, whose transitions all read the
    // cluster's CTRR groups: unlocked, under its lock; locked, without it.
    for locked in [false, true] {
        let ns = contended(locked);
        std::println!("EXITS svc+eret pes=4 ctrr_locked={locked} ns_per_transition={ns}");
    }
    // The parts of one transition, at EL1 after an SVC.
    let mut machine = user(false);
    exit(&mut machine, SVC);
    let parts: [(&str, Round); 6] = [
        ("cpu-take+return", |machine| {
            let exception = crate::machine::cpu::Exception::synchronous(
                crate::machine::exception::Class::SupervisorCall,
                0,
                USER + 4,
            );
            let pstate = machine.cpu.pstate;
            machine.cpu.take(exception);
            machine.cpu.set_pstate(pstate);
        }),
        ("transitioned", |machine| {
            machine.transitioned();
            machine.host.regimes.clear();
        }),
        ("sync-host-regime", |machine| {
            machine.sync_host_regime();
            machine.host.regimes.clear();
        }),
        ("reopen-pointers", |machine| machine.reopen_pointers()),
        ("forget+variant", |machine| {
            machine.forget_derived();
            machine.current_variant(false, false);
        }),
        ("variant", |machine| {
            machine.current_variant(false, false);
        }),
    ];
    for (name, part) in parts {
        let ns = time(&mut machine, 1, part);
        std::println!("EXITS part={name} ns={ns}");
    }
}

/// Nanoseconds per SVC or ERET transition of four PEs of one M2 cluster
/// running at once, the slowest PE's.
fn contended(locked: bool) -> u64 {
    use crate::machine::ctrr::Field;
    let cluster = crate::machine::shared::Shared::<crate::machine::ctrr::Cluster>::default();
    if locked {
        for level in 0..2 {
            cluster.borrow_mut().write(level, Field::Lock, 1).unwrap();
        }
    }
    let start = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        let runs: std::vec::Vec<_> = (0..4)
            .map(|_| {
                let (cluster, start) = (cluster.clone(), &start);
                scope.spawn(move || {
                    let mut machine = user_on(stela_contracts::Chip::AppleM2, true);
                    machine.cpu.ctrr = cluster;
                    start.wait();
                    time(&mut machine, 2, system_call)
                })
            })
            .collect();
        runs.into_iter()
            .map(|run| run.join().unwrap())
            .max()
            .unwrap()
    })
}
