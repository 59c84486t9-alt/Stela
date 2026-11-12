// SPDX-License-Identifier: GPL-2.0-only
//! Where an I/O command's start and finish spend their time on the host, for
//! a report: each part's calls and time-stamp counter ticks since the last
//! [`take`]. A part costs two counter reads and two relaxed adds.

use crate::Clock;
use core::sync::atomic::{AtomicU64, Ordering};

/// The parts, in the order a command meets them. `Start` holds `Doorbell`,
/// and `Advance` holds `Status` and `Ring`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// A start's look for asynchronous events and namespace changes.
    Rescan,
    /// A start on the I/O queue: tag, pages, data copy, data pointers,
    /// submission entry and doorbell.
    Start,
    /// An I/O submission doorbell write.
    Doorbell,
    /// A look at the I/O completion queue: its completions' ends, read data
    /// copies included, retries and deadlines.
    Advance,
    /// A controller status read after a completion that looked invalid.
    Status,
    /// An I/O completion doorbell write.
    Ring,
}

pub const PARTS: [&str; 6] = ["rescan", "start", "doorbell", "advance", "status", "ring"];

static TIMES: [[AtomicU64; 2]; PARTS.len()] =
    [const { [const { AtomicU64::new(0) }; 2] }; PARTS.len()];

/// Each part's calls and ticks since the last call, by [`PARTS`].
pub fn take() -> [[u64; 2]; PARTS.len()] {
    core::array::from_fn(|part| {
        [
            TIMES[part][0].swap(0, Ordering::Relaxed),
            TIMES[part][1].swap(0, Ordering::Relaxed),
        ]
    })
}

/// Run `call`, counting it as `part`.
pub(super) fn timed<T>(part: Part, call: impl FnOnce() -> T) -> T {
    let since = Clock::ticks();
    let result = call();
    TIMES[part as usize][0].fetch_add(1, Ordering::Relaxed);
    TIMES[part as usize][1].fetch_add(Clock::ticks().wrapping_sub(since), Ordering::Relaxed);
    result
}
