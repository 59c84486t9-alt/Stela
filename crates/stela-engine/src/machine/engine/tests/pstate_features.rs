//! PSTATE fields whose features the host decides: DIT is kept on every
//! chip, whether or not the host gives its timing guarantee.
use super::*;

#[test]
fn dit_is_kept_without_the_host_timing_guarantee() {
    const MSR_DIT_1: u32 = 0xd503_415f;
    const MSR_DIT_X0: u32 = 0xd51b_42a0;
    const MRS_X0_DIT: u32 = 0xd53b_42a0;
    let mut machine = machine(&[]);
    assert_eq!(machine.timing_target(), None);
    for word in [MSR_DIT_1, MSR_DIT_X0] {
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.cpu.state.x[0] = 1 << 24;
        machine.system_instruction(word).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4, "{word:#x}");
        assert!(machine.cpu.pstate.dit, "{word:#x}");
    }
    machine.cpu.pc = BASE;
    machine.cpu.state.x[0] = 0;
    machine.system_instruction(MRS_X0_DIT).unwrap();
    assert_eq!(machine.cpu.state.x[0], 1 << 24);
}

#[test]
fn ssbs_stays_writable() {
    const MSR_SSBS_1: u32 = 0xd503_413f;
    let mut machine = machine(&[]);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.system_instruction(MSR_SSBS_1).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    assert!(machine.cpu.pstate.ssbs);
}

#[test]
fn a_parallel_machine_never_compiles_pstate_dit_code_for_a_timing_target() {
    use super::parallel::{Hub, Kick};
    struct NoKick;
    impl Kick for NoKick {
        fn kick(&self, _pe: usize) {}
    }
    let mut machine = machine(&[0xd503_201f]);
    machine.target = TargetCpu::DATA_INDEPENDENT_TIMING_TIERS[2].with_doit();
    assert!(machine.timing_target().is_some());
    let hub = Hub::new(1, NoKick);
    hub.set_live(0, true);
    machine.enter_parallel(hub).unwrap();
    // Its plain-ordering atomics would race the other PEs.
    assert_eq!(machine.timing_target(), None);
}
