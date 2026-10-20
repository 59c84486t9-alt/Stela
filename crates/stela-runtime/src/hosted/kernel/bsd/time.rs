//! Calls that carry `mach_absolute_time` values. The guest's absolute time
//! is the generic timer's 24 MHz count of the host's nanosecond absolute
//! time ([`host::counter_at`]); a value crossing the boundary is converted.
//! Wall-clock and `timespec` arguments are the same on both kernels and stay
//! with the forwarded families. `kevent` and `kevent64` timers in absolute
//! units are [`super::timer`]'s.
use super::{Call, EFAULT, Kernel, Outcome, forward};
use crate::hosted::{host, memory};
use anyhow::{Result, bail};

/// `KERN_CLOCK_MACH_ABSOLUTE_TIME`, the eventlink deadline clock.
const KERN_CLOCK_MACH_ABSOLUTE_TIME: u64 = 1;

pub(super) const CALLS: &[&str] = &[
    "gettimeofday",
    "mach_eventlink_wait_until",
    "mach_eventlink_signal_wait_until",
    "kevent",
    "kevent64",
];

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "gettimeofday" => gettimeofday(kernel, call)?,
        "mach_eventlink_wait_until" => eventlink_wait(kernel, call, 2, 3)?,
        "mach_eventlink_signal_wait_until" => eventlink_wait(kernel, call, 3, 4)?,
        "kevent" | "kevent64" => return super::timer::call(kernel, call),
        _ => return Ok(None),
    }))
}

/// `gettimeofday(tp, tzp, mach_absolute_time)`: the third argument
/// receives the absolute time the wall time was read at.
fn gettimeofday(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let target = call.argument(2);
    let mut absolute = 0u64;
    let mut host_call = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    if target != 0 {
        host_call.arguments[2] = &raw mut absolute as u64;
    }
    let outcome = forward(kernel, &host_call)?;
    if target != 0
        && matches!(outcome, Outcome::Return(..))
        && !memory::write_u64(target, host::counter_at(absolute))
    {
        return Ok(Outcome::Error(EFAULT));
    }
    Ok(outcome)
}

/// An eventlink wait's deadline is absolute time on its clock.
fn eventlink_wait(
    kernel: &mut Kernel,
    call: &Call,
    deadline: usize,
    clock: usize,
) -> Result<Outcome> {
    if call.argument(clock) != KERN_CLOCK_MACH_ABSOLUTE_TIME {
        bail!(
            "{} on clock {}: only KERN_CLOCK_MACH_ABSOLUTE_TIME deadlines are defined",
            call.entry.name,
            call.argument(clock)
        );
    }
    let mut host_call = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    let value = call.argument(deadline);
    if value != 0 && value != u64::MAX {
        host_call.arguments[deadline] = host::nanoseconds_at(value);
    }
    forward(kernel, &host_call)
}
