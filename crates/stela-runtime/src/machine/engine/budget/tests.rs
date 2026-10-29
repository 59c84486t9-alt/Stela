use super::super::{ExitKind, NativeExit, Stop, SystemRegister, tests::machine};
use super::{Deadline, RunBudget};

const DAIFSET_I: u32 = 0xd503_42df;
const DAIFCLR_I: u32 = 0xd503_42ff;

fn system(pc: u64) -> NativeExit {
    NativeExit::Exit {
        next_pc: pc,
        kind: ExitKind::System as u64,
    }
}

#[test]
fn untimed_block_limit_adds_no_counter_read() {
    let mut machine = machine(&[]);
    machine.statistics.blocks = 1;
    let reads = machine.host.counter_reads;
    assert_eq!(machine.run(1), Stop::Budget);
    assert_eq!(machine.host.counter_reads, reads);
    assert!(machine.host.installed.is_empty());
}

#[test]
fn zero_duration_yields_before_execution() {
    let mut machine = machine(&[DAIFSET_I]);
    let pc = machine.cpu.pc;
    assert_eq!(
        machine.run_with_budget(RunBudget {
            blocks: 0,
            host_ticks: Some(0)
        }),
        Stop::Budget
    );
    assert_eq!(machine.cpu.pc, pc);
    assert_eq!(machine.cpu.retired, 0);
    assert!(machine.host.installed.is_empty());
}

#[test]
fn elapsed_host_time_yields_and_resumes_after_completed_effects() {
    let mut machine = machine(&[DAIFSET_I, DAIFCLR_I]);
    let pc = machine.cpu.pc;
    machine.cpu.pstate.daif = 0;
    machine.host.execute_ticks = 100;
    machine.host.exits = vec![system(pc), system(pc + 4)];
    let budget = RunBudget {
        blocks: 10,
        host_ticks: Some(50),
    };
    assert_eq!(machine.run_with_budget(budget), Stop::Budget);
    assert_eq!((machine.statistics.blocks, machine.cpu.retired), (1, 1));
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.daif), (pc + 4, 2));
    assert_eq!(machine.run_with_budget(budget), Stop::Budget);
    assert_eq!((machine.statistics.blocks, machine.cpu.retired), (2, 2));
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.daif), (pc + 8, 0));
    assert!(machine.host.exits.is_empty());
}

#[test]
fn host_counter_wrap_still_yields_after_the_entered_block() {
    let mut machine = machine(&[DAIFSET_I]);
    let pc = machine.cpu.pc;
    machine.slice_end = u64::MAX;
    machine.host.now = u64::MAX - 49;
    machine.host.execute_ticks = 100;
    machine.host.exits = vec![system(pc)];
    assert_eq!(
        machine.run_with_budget(RunBudget {
            blocks: 10,
            host_ticks: Some(50)
        }),
        Stop::Budget
    );
    assert_eq!(machine.host.now, 50);
    assert_eq!((machine.statistics.blocks, machine.cpu.retired), (1, 1));
    assert_eq!(machine.cpu.pc, pc + 4);
}

#[test]
fn idle_wait_arms_the_earlier_host_deadline_and_clears_it_on_yield() {
    let mut machine = machine(&[0xd503_207f]); // wfi
    let pc = machine.cpu.pc;
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CVAL_EL0, 0, 10_000);
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CTL_EL0, 0, 1);
    machine.derived_changed();
    machine.host.exits = vec![system(pc)];
    assert_eq!(
        machine.run_with_budget(RunBudget {
            blocks: 10,
            host_ticks: Some(50)
        }),
        Stop::Budget
    );
    assert_eq!(machine.host.timers, [Some(50), None]);
    assert_eq!(machine.cpu.read(SystemRegister::CNTV_CVAL_EL0), 10_000);
    assert_eq!(machine.cpu.retired, 1);
    assert_eq!(machine.cpu.pc, pc);
    assert!(machine.waits_for_interrupt());
    machine.host.now = 10_000;
    machine.breakpoints.push(pc + 4);
    assert_eq!(
        machine.run_with_budget(RunBudget {
            blocks: 10,
            host_ticks: Some(50)
        }),
        Stop::Breakpoint(pc + 4)
    );
    assert_eq!(machine.cpu.retired, 1);
    assert!(!machine.waits_for_interrupt());
}

#[test]
fn duration_and_timer_comparisons_cross_counter_wrap() {
    let deadline = Deadline::new(u64::MAX - 5, 10);
    assert_eq!(deadline.remaining(2), Some(2));
    assert_eq!(deadline.timer(2, 100), Some(4));
    assert_eq!(deadline.timer(2, 1), Some(2));
    assert_eq!(deadline.remaining(4), None);
    assert_eq!(deadline.timer(4, 100), None);
}
