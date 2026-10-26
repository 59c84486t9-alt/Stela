//! Calls that carry `mach_absolute_time` values. The guest's absolute time
//! is the generic timer's 24 MHz count of the host's nanosecond absolute
//! time ([`host::counter_at`]); a value crossing the boundary is converted.
//! Wall-clock and `timespec` arguments are the same on both kernels and stay
//! with the forwarded families. `kevent` and `kevent64` timers in absolute
//! units are [`super::timer`]'s. `gettimeofday` and `settimeofday` also
//! refresh the commpage's timestamp ([`commpage::refresh_time`]).
use super::{Call, Kernel, Outcome, forward};
use crate::hosted::darwin::{EFAULT, EINVAL};
use crate::hosted::{commpage, host, memory};
use anyhow::Result;

/// `KERN_CLOCK_MACH_ABSOLUTE_TIME`, the eventlink deadline clock.
const KERN_CLOCK_MACH_ABSOLUTE_TIME: u64 = 1;

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "gettimeofday" => gettimeofday(kernel, call)?,
        "settimeofday" => settimeofday(kernel, call)?,
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
    // Reading the time refreshes the commpage's timestamp
    // (`clock_gettimeofday_and_absolute_time`), the host's and so the
    // guest's.
    if call.argument(0) != 0 || target != 0 {
        commpage::refresh_time();
    }
    if target != 0
        && matches!(outcome, Outcome::Return(..))
        && !memory::write_u64(target, host::counter_at(absolute))
    {
        return Ok(Outcome::Error(EFAULT));
    }
    Ok(outcome)
}

/// `settimeofday(tv, tzp)`: the host's calendar is this machine's; a set
/// refreshes the commpage's timestamp (`clock_set_calendar_microtime`).
fn settimeofday(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let outcome = forward(kernel, call)?;
    commpage::refresh_time();
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
        crate::hosted::unsupported::refuse!(
            EINVAL,
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
