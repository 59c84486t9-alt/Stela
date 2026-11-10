//! FP instructions under FPCR trap enables: the TrappedFP exception only for
//! an enabled exception the instruction raises.
use super::*;
use crate::floating::Trapped;
use stela_compiler::aarch64::{
    FloatingPointOperation,
    floating::{DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_EXCEPTION_ENABLE_SHIFT},
};

const FDIV_D0_D1_D2: u32 = 0x1e62_1820;
const ONE: u64 = 0x3ff0_0000_0000_0000;

fn fdiv() -> FloatingPointOperation {
    FloatingPointOperation::decode(FDIV_D0_D1_D2)
        .unwrap()
        .unwrap()
}

#[test]
fn an_enabled_exception_takes_the_trapped_fp_exception_at_its_instruction() {
    let mut machine = machine(&[]);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.cpu.state.fpcr = DIVIDE_BY_ZERO << FPCR_EXCEPTION_ENABLE_SHIFT;
    machine.cpu.state.v[0] = [7, 7];
    machine.cpu.state.v[1] = [ONE, 0];
    machine.cpu.state.v[2] = [0, 0];
    let retired = machine.cpu.retired;
    let trapped = machine
        .complete_floating_point(FDIV_D0_D1_D2, &fdiv())
        .unwrap_err();
    assert_eq!(
        trapped,
        Trapped {
            exceptions: DIVIDE_BY_ZERO
        }
    );
    machine
        .completing(BASE, |machine| {
            machine.take_floating_point_exception(trapped)
        })
        .unwrap();
    // EC 0x2C, IL, TFV and DZF.
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xb280_0002);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    assert_eq!(machine.cpu.retired, retired);
    assert_eq!(machine.cpu.state.v[0], [7, 7]);
    assert_eq!(machine.cpu.state.fpsr, 0);
}

#[test]
fn enabled_traps_complete_an_instruction_that_raises_none_of_them() {
    let mut machine = machine(&[]);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.cpu.state.fpcr = EXCEPTIONS << FPCR_EXCEPTION_ENABLE_SHIFT;
    machine.cpu.state.v[1] = [ONE, 0];
    machine.cpu.state.v[2] = [ONE, 0];
    machine
        .complete_floating_point(FDIV_D0_D1_D2, &fdiv())
        .unwrap();
    machine.completing(BASE, Machine::next).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    assert_eq!(machine.cpu.state.v[0], [ONE, 0]);
    assert_eq!(machine.cpu.state.fpsr, 0);
}
