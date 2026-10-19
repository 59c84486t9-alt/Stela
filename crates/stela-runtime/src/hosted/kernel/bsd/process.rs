//! Process lifetime: `exit` ends the run with the guest's status, which
//! becomes the host process's own (`bsd/kern/kern_exit.c` keeps its low
//! eight bits). Creating processes or replacing this image needs the hosted
//! runtime in the child and stays refused by name until it is implemented.
use super::{Call, Kernel, Outcome, Pe};
use crate::hosted::Termination;
use anyhow::Result;

pub(super) fn call(kernel: &mut Kernel, _pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "exit" => {
            kernel.termination = Some(Termination::Exited(call.argument(0) as i32));
            Some(Outcome::JustReturn)
        }
        _ => None,
    })
}
