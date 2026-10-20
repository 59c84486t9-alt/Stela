//! `EVFILT_TIMER` in the guest's timebase (`bsd/kern/kern_event.c`
//! `filt_timervalidate`). A timer whose unit is `NOTE_MACHTIME` takes its
//! interval, or with `NOTE_ABSOLUTE` its deadline, in `mach_absolute_time`
//! (or with `NOTE_MACH_CONTINUOUS_TIME` `mach_continuous_time`) units, and
//! with `NOTE_LEEWAY` its leeway in `ext[1]` likewise; the kernel keeps the
//! leeway in absolute units whatever the unit, and a delivered timer event
//! reports it there. The guest's units are the 24 MHz counter's, the host's
//! nanoseconds ([`host::counter_at`]): a change is converted before the host
//! kernel validates it, rounding up so that a timer never fires early and a
//! value read back is the one set, and an event's leeway after.
//!
//! The three layouts that carry timers: `struct kevent` (`kevent`, no
//! `ext`), `struct kevent64_s` (`kevent64`) and `struct kevent_qos_s`
//! (`kevent_qos`, `kevent_id`).
use super::aio::{Aio, Rewrite};
use super::kqworkq::{EV_ERROR, Kevent};
use super::{Call, EFAULT, Kernel, Outcome};
use crate::hosted::{host, memory};
use anyhow::Result;
use std::sync::Arc;

const EVFILT_TIMER: i16 = -7;
const NOTE_SECONDS: u32 = 0x1;
const NOTE_USECONDS: u32 = 0x2;
const NOTE_NSECONDS: u32 = 0x4;
const NOTE_ABSOLUTE: u32 = 0x8;
const NOTE_LEEWAY: u32 = 0x10;
const NOTE_MACHTIME: u32 = 0x100;
const UNITS: u32 = NOTE_SECONDS | NOTE_USECONDS | NOTE_NSECONDS | NOTE_MACHTIME;

/// Where a layout keeps the fields a timer converts and a kernel knote
/// fills; every layout starts with ident, filter and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Layout {
    pub(super) size: usize,
    fflags: usize,
    data: usize,
    /// `ext[1]`, absent from `struct kevent`.
    leeway: Option<usize>,
    /// `ext[0]` and how many `ext` words follow it.
    ext: Option<(usize, usize)>,
    /// `qos` and `xflags`, which only `struct kevent_qos_s` has.
    qos: Option<(usize, usize)>,
}

/// `struct kevent`: ident, filter, flags, fflags, data, udata.
const KEVENT: Layout = Layout {
    size: 32,
    fflags: 12,
    data: 16,
    leeway: None,
    ext: None,
    qos: None,
};
/// `struct kevent64_s`: then `ext[2]`.
pub(super) const KEVENT64: Layout = Layout {
    size: 48,
    fflags: 12,
    data: 16,
    leeway: Some(40),
    ext: Some((32, 2)),
    qos: None,
};
/// `struct kevent_qos_s`: ident, filter, flags, qos, udata, fflags,
/// xflags, data, `ext[4]`.
pub(super) const KEVENT_QOS: Layout = Layout {
    size: 72,
    fflags: 24,
    data: 32,
    leeway: Some(48),
    ext: Some((40, 4)),
    qos: Some((12, 28)),
};

impl Layout {
    /// Fill the event `bytes` as `knote_fill_kevent` does for a kernel
    /// knote of `filter` on `ident` whose state is `fflags` and `ext`
    /// (the rest of `ext`, `data`, `qos` and `xflags` zero), keeping its
    /// flags and user data.
    pub(super) fn fill_kernel_event(
        self,
        bytes: &mut [u8],
        ident: u64,
        filter: i16,
        fflags: u32,
        ext: [u64; 2],
    ) {
        bytes[..8].copy_from_slice(&ident.to_le_bytes());
        bytes[8..10].copy_from_slice(&filter.to_le_bytes());
        bytes[self.fflags..self.fflags + 4].copy_from_slice(&fflags.to_le_bytes());
        bytes[self.data..self.data + 8].fill(0);
        if let Some((at, words)) = self.ext {
            bytes[at..at + words * 8].fill(0);
            for (index, word) in ext.iter().enumerate() {
                bytes[at + index * 8..at + index * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
        }
        if let Some((qos, xflags)) = self.qos {
            bytes[qos..qos + 4].fill(0);
            bytes[xflags..xflags + 4].fill(0);
        }
    }
}

/// Host nanoseconds for guest counter `ticks`, rounded up, saturating at
/// `limit`.
fn host_units(ticks: u64, limit: u64) -> u64 {
    let nanoseconds = (u128::from(ticks) * 125).div_ceil(3);
    nanoseconds.min(u128::from(limit)) as u64
}

/// A timer change's interval or deadline, and its leeway, in host units:
/// `(data, leeway)`, or `None` for a change that needs none.
fn change_to_host(filter: i16, fflags: u32, data: i64, leeway: u64) -> Option<(i64, u64)> {
    if filter != EVFILT_TIMER || fflags & UNITS != NOTE_MACHTIME {
        return None;
    }
    let data = if fflags & NOTE_ABSOLUTE != 0 {
        // The deadline is unsigned (`(uint64_t)kev->data`).
        host_units(data as u64, u64::MAX) as i64
    } else if data < 0 {
        // A negative interval fires at once, in any unit.
        data
    } else {
        host_units(data as u64, i64::MAX as u64) as i64
    };
    let leeway = if fflags & NOTE_LEEWAY != 0 {
        host_units(leeway, u64::MAX)
    } else {
        leeway
    };
    Some((data, leeway))
}

/// A delivered timer event's leeway, kept in absolute units, in the guest's.
fn event_leeway(filter: i16, flags: u16, leeway: u64) -> Option<u64> {
    (filter == EVFILT_TIMER && flags & EV_ERROR == 0 && leeway != 0)
        .then(|| host::counter_at(leeway))
}

/// `change` as the host kernel takes it.
pub(super) fn qos_change_to_host(change: &Kevent) -> Kevent {
    let mut host = *change;
    if let Some((data, leeway)) =
        change_to_host(change.filter, change.fflags, change.data, change.ext[1])
    {
        host.data = data;
        host.ext[1] = leeway;
    }
    host
}

/// The host kernel's result for `change` (`EV_ERROR` echoes the change)
/// or delivered event, as the guest reads it.
pub(super) fn qos_event_to_guest(event: &mut Kevent, change: Option<&Kevent>) {
    match change {
        Some(change) if event.flags & EV_ERROR != 0 => event.ext[1] = change.ext[1],
        _ => {
            if let Some(leeway) = event_leeway(event.filter, event.flags, event.ext[1]) {
                event.ext[1] = leeway;
            }
        }
    }
}

fn field(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn filter_and_flags(bytes: &[u8]) -> (i16, u16) {
    (
        i16::from_le_bytes([bytes[8], bytes[9]]),
        u16::from_le_bytes([bytes[10], bytes[11]]),
    )
}

/// A host copy of the `count` changes at `changes` to the kqueue `kqueue`
/// with their timers converted and their asynchronous I/O knotes
/// rewritten ([`Aio::change_to_host`], whose rewrites it adds to
/// `rewrites`), or `None` when none needs it (or the list is unreadable,
/// which the host's copy-in reports at the same change).
fn host_changes(
    layout: Layout,
    kqueue: i32,
    changes: u64,
    count: i64,
    aio: &Aio,
    rewrites: &mut Vec<Rewrite>,
) -> Option<Vec<u8>> {
    let count = usize::try_from(count).ok().filter(|&count| count > 0)?;
    let mut list = memory::read(changes, count.checked_mul(layout.size)?)?;
    let mut converted = false;
    for entry in list.chunks_exact_mut(layout.size) {
        let (filter, flags) = filter_and_flags(entry);
        if let Some(rewrite) = aio.change_to_host(kqueue, field(entry, 0), filter, flags) {
            entry[..8].copy_from_slice(&rewrite.host.0.to_le_bytes());
            entry[8..10].copy_from_slice(&rewrite.host.1.to_le_bytes());
            rewrites.push(rewrite);
            converted = true;
            continue;
        }
        let fflags =
            u32::from_le_bytes(entry[layout.fflags..layout.fflags + 4].try_into().unwrap());
        let data = field(entry, layout.data) as i64;
        let leeway = layout.leeway.map_or(0, |at| field(entry, at));
        let Some((data, leeway)) = change_to_host(filter, fflags, data, leeway) else {
            continue;
        };
        entry[layout.data..layout.data + 8].copy_from_slice(&data.to_le_bytes());
        if let Some(at) = layout.leeway {
            entry[at..at + 8].copy_from_slice(&leeway.to_le_bytes());
        }
        converted = true;
    }
    converted.then_some(list)
}

/// Convert the leeway of the `count` events the host wrote at `events`;
/// false when the list cannot be rewritten.
fn events_to_guest(layout: Layout, events: u64, count: u64) -> bool {
    let Some(at) = layout.leeway else {
        return true;
    };
    for index in 0..count {
        let entry = events + index * layout.size as u64;
        let Some(bytes) = memory::read(entry, layout.size) else {
            return false;
        };
        let (filter, flags) = filter_and_flags(&bytes);
        if let Some(leeway) = event_leeway(filter, flags, field(&bytes, at))
            && !memory::write_u64(entry + at as u64, leeway)
        {
            return false;
        }
    }
    true
}

/// `kevent(fd, changelist, nchanges, eventlist, nevents, timeout)`,
/// `kevent64(fd, changelist, nchanges, eventlist, nevents, flags,
/// timeout)` and an ordinary kqueue's `kevent_qos(fd, changelist,
/// nchanges, eventlist, nevents, data_out, data_available, flags)`: the
/// host kernel's, with timers in host units. The change list is copied
/// for the host only when a timer needs it; an `EV_ERROR` result then
/// echoes the host's copy, whose leeway is converted back.
pub(super) fn kevent(kernel: &mut Kernel, call: &Call, layout: Layout) -> Result<Outcome> {
    let aio = Arc::clone(&kernel.process.aio);
    let mut rewrites = Vec::new();
    let changes = host_changes(
        layout,
        call.argument(0) as u32 as i32,
        call.argument(1),
        call.argument(2) as u32 as i32 as i64,
        &aio,
        &mut rewrites,
    );
    let mut host_call = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    if let Some(list) = &changes {
        host_call.arguments[1] = list.as_ptr() as u64;
    }
    let outcome = super::forward(kernel, &host_call)?;
    if let Outcome::Return(count, _) = outcome
        && !(events_to_guest(layout, call.argument(3), count)
            && aio.events_to_guest(layout, call.argument(3), count, &rewrites))
    {
        return Ok(Outcome::Error(EFAULT));
    }
    Ok(outcome)
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "kevent" => kevent(kernel, call, KEVENT)?,
        "kevent64" => kevent(kernel, call, KEVENT64)?,
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::forward;

    const NOTE_MACH_CONTINUOUS_TIME: u32 = 0x80;

    #[test]
    fn machtime_timers_take_host_nanoseconds() {
        // 24 ticks are a microsecond.
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME, 24, 0),
            Some((1000, 0))
        );
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME | NOTE_LEEWAY, 24_000_000, 240),
            Some((1_000_000_000, 10_000))
        );
        // Rounded up: one tick is 41.67 ns, and reads back as one tick.
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME, 1, 0),
            Some((42, 0))
        );
        assert_eq!(host::counter_at(42), 1);
        for ticks in [1u64, 2, 3, 7, 24, 1_000_003, 1 << 40] {
            assert_eq!(host::counter_at(host_units(ticks, u64::MAX)), ticks);
        }
        // Absolute deadlines, continuous or not, are unsigned and saturate.
        assert_eq!(
            change_to_host(
                EVFILT_TIMER,
                NOTE_MACHTIME | NOTE_ABSOLUTE | NOTE_MACH_CONTINUOUS_TIME,
                -1,
                0
            ),
            Some((-1, 0))
        );
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME, i64::MAX, 0),
            Some((i64::MAX, 0))
        );
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME, -5, 0),
            Some((-5, 0))
        );
        // Other units and filters are the host's already.
        assert_eq!(change_to_host(EVFILT_TIMER, NOTE_NSECONDS, 24, 0), None);
        assert_eq!(
            change_to_host(EVFILT_TIMER, NOTE_MACHTIME | NOTE_SECONDS, 24, 0),
            None
        );
        assert_eq!(change_to_host(-1, NOTE_MACHTIME, 24, 0), None);
        // A delivered timer reports its leeway in absolute units.
        assert_eq!(event_leeway(EVFILT_TIMER, 0, 10_000), Some(240));
        assert_eq!(event_leeway(EVFILT_TIMER, EV_ERROR, 10_000), None);
        assert_eq!(event_leeway(EVFILT_TIMER, 0, 0), None);
    }

    #[test]
    fn a_host_kqueue_fires_a_converted_timer() {
        // SAFETY: a new kqueue this test owns.
        let queue = unsafe { libc::kqueue() };
        assert!(queue >= 0);
        // A 2400-tick (100 us) interval timer with 24 ticks of leeway.
        let mut change = [0u8; 48];
        change[0..8].copy_from_slice(&7u64.to_le_bytes());
        change[8..10].copy_from_slice(&EVFILT_TIMER.to_le_bytes());
        change[10..12].copy_from_slice(&(0x1u16 | 0x10).to_le_bytes()); // EV_ADD | EV_ONESHOT
        change[12..16].copy_from_slice(&(NOTE_MACHTIME | NOTE_LEEWAY).to_le_bytes());
        change[16..24].copy_from_slice(&2400i64.to_le_bytes());
        change[40..48].copy_from_slice(&24u64.to_le_bytes());
        let mut rewrites = Vec::new();
        let aio = Aio::default();
        let list = host_changes(
            KEVENT64,
            queue,
            change.as_ptr() as u64,
            1,
            &aio,
            &mut rewrites,
        )
        .unwrap();
        assert!(rewrites.is_empty());
        assert_eq!(field(&list, 16), 100_000);
        assert_eq!(field(&list, 40), 1000);
        let mut event = [0u8; 48];
        let returned = forward::bsd(
            super::super::number_of("kevent64"),
            &[
                queue as u64,
                list.as_ptr() as u64,
                1,
                event.as_mut_ptr() as u64,
                1,
                0,
                0,
            ],
        );
        assert!(!returned.carry);
        assert_eq!(returned.rax, 1);
        assert!(events_to_guest(KEVENT64, event.as_ptr() as u64, 1));
        assert_eq!(field(&event, 0), 7);
        assert_eq!(field(&event, 40), 24);
        // SAFETY: the kqueue this test opened.
        unsafe { libc::close(queue) };
    }
}
