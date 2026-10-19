//! The platform call (`osfmk/arm64/machine_routines.c` `platform_syscall`):
//! X3 selects the operation. Code 2 sets the thread's `cthread_self`, which
//! is TPIDRRO_EL0; code 3 returns it in X0. The removed cache-flush codes
//! and unknown codes return with every register unchanged, as there.
use super::{Kernel, Trap};
use crate::machine::system::Register;
use anyhow::Result;

const SET_CTHREAD_SELF: u64 = 2;
const GET_CTHREAD_SELF: u64 = 3;

pub(super) fn call(kernel: &mut Kernel, trap: &mut Trap) -> Result<()> {
    kernel.count("platform_syscall");
    match trap.x(3) as u32 as u64 {
        SET_CTHREAD_SELF => {
            let value = trap.x(0);
            trap.cpu.registers.set_raw(Register::TPIDRRO_EL0, 0, value);
        }
        GET_CTHREAD_SELF => {
            let value = trap.cpu.read(Register::TPIDRRO_EL0);
            trap.set_x(0, value);
        }
        _ => {}
    }
    Ok(())
}
