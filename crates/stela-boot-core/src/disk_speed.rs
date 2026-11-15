//! Whether a disk answers reads fast enough for macOS to start on it.
//!
//! macOS starts with a storm of small reads, and its daemons must check in
//! within a fixed wall-clock time: IOKit panics with `IOKit Daemon
//! (kernelmanagerd) stall[0], (60s): registry root held busy, kernelmanagerd
//! has not checked in` when kernelmanagerd has not done so 60 s after the
//! registry went busy waiting for it. Guest time follows wall time, so only
//! the disk's speed decides it.
//!
//! The numbers come from boot logs. A boot that reached the Language
//! Chooser on an SSD (#138) made about 33,000 reads, 720 MB, in its first
//! 70 s, each answered in 0.3-0.9 ms with the disk busy 20-50% of the time.
//! The boots that panicked so answered one read in 3-8 ms with the disk
//! busy all the time: a 5400 rpm 80 GB SATA disk at 115-150 reads a second
//! even with 32 queued (#132), a 5400 rpm 1 TB SATA disk at 170-300 (#133)
//! and a USB disk at 70-130 (#146). So a boot needs about [`BOOT_READS`]
//! reads within [`BOOT_SECONDS`]: at most [`SLOWEST_READ_US`] a read, and
//! [`SLOWEST_SEQUENTIAL_KIB_S`] for its bytes.
//!
//! The disk picker measures each disk it offers ([`measure`]), read only and
//! bounded, and cautions on one below that ([`caution`]).
use alloc::{format, string::String, vec::Vec};
use stela_drivers::block::Rotation;

/// The reads a boot makes before kernelmanagerd checks in, about.
pub const BOOT_READS: u64 = 30_000;
/// The bytes those reads move, in MiB, about.
pub const BOOT_MIB: u64 = 720;
/// The time kernelmanagerd has to check in.
pub const BOOT_SECONDS: u64 = 60;
/// The most a read may take on average for a boot to make it: 2 ms.
pub const SLOWEST_READ_US: u64 = BOOT_SECONDS * 1_000_000 / BOOT_READS;
/// The least sequential rate for a boot's bytes: 12 MiB a second.
pub const SLOWEST_SEQUENTIAL_KIB_S: u64 = BOOT_MIB * 1024 / BOOT_SECONDS;

/// A random read's size: macOS's reads at start are 4-30 KiB.
pub const RANDOM_BYTES: u64 = 4096;
/// A sequential read's size.
pub const SEQUENTIAL_BYTES: u64 = 1 << 20;
/// The most random reads, and the time after which no more start.
pub const RANDOM_READS: usize = 64;
pub const RANDOM_MICROS: u64 = 1_000_000;
/// The most sequential reads, and the time after which no more start.
pub const SEQUENTIAL_READS: usize = 32;
pub const SEQUENTIAL_MICROS: u64 = 500_000;

/// What [`measure`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Speed {
    /// The median time of a random [`RANDOM_BYTES`] read.
    pub random_us: u64,
    /// The rate of consecutive [`SEQUENTIAL_BYTES`] reads after the first.
    pub sequential_kib_s: u64,
}

/// A deterministic spread of positions: xorshift64.
fn next(state: &mut u64) -> u64 {
    let mut x = (*state).max(1);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Measure a disk of `blocks` blocks of `block_bytes`: random reads at
/// positions spread over the whole disk from `seed`, then consecutive reads
/// from one of them, each phase bounded by its count and its time. `read`
/// reads `count` blocks at a block and says whether it could; `now_us` is a
/// monotonic clock in microseconds. A read that has started cannot be cut
/// short, so a disk that takes seconds for one read (spinning up) takes that
/// long once; the median leaves that read out. `None` for a disk too small
/// for the reads or one that failed a read: nothing is said of its speed.
pub fn measure(
    blocks: u64,
    block_bytes: u64,
    seed: u64,
    mut read: impl FnMut(u64, u64) -> bool,
    mut now_us: impl FnMut() -> u64,
) -> Option<Speed> {
    if block_bytes == 0 || block_bytes > RANDOM_BYTES || !RANDOM_BYTES.is_multiple_of(block_bytes) {
        return None;
    }
    let random_blocks = RANDOM_BYTES / block_bytes;
    let sequential_blocks = SEQUENTIAL_BYTES / block_bytes;
    let span = sequential_blocks * SEQUENTIAL_READS as u64;
    if blocks < span * 2 {
        return None;
    }
    let mut state = seed;
    let slots = (blocks - random_blocks) / random_blocks;
    let started = now_us();
    let mut times = Vec::with_capacity(RANDOM_READS);
    while times.len() < RANDOM_READS && now_us().saturating_sub(started) < RANDOM_MICROS {
        let lba = next(&mut state) % slots * random_blocks;
        let before = now_us();
        if !read(lba, random_blocks) {
            return None;
        }
        times.push(now_us().saturating_sub(before));
    }
    times.sort_unstable();
    let random_us = times[times.len() / 2];
    let first = next(&mut state) % (blocks - span) / random_blocks * random_blocks;
    let mut lba = first;
    let started = now_us();
    let mut after_first = None;
    let mut reads = 0;
    while reads < SEQUENTIAL_READS && now_us().saturating_sub(started) < SEQUENTIAL_MICROS {
        if !read(lba, sequential_blocks) {
            return None;
        }
        lba += sequential_blocks;
        reads += 1;
        // The first read's seek is not part of the rate.
        after_first.get_or_insert_with(&mut now_us);
    }
    let (from, counted) = match after_first {
        Some(at) if reads > 1 => (at, reads - 1),
        _ => (started, reads),
    };
    let micros = now_us().saturating_sub(from).max(1);
    let sequential_kib_s = counted as u64 * (SEQUENTIAL_BYTES / 1024) * 1_000_000 / micros;
    Some(Speed {
        random_us,
        sequential_kib_s,
    })
}

/// Microseconds as milliseconds with one decimal.
fn millis(micros: u64) -> String {
    format!("{}.{} ms", micros / 1000, micros % 1000 / 100)
}

/// The picker's caution for a disk it lets the user choose but on which
/// macOS may never finish starting: one [`measure`] found slower than a
/// boot needs, or, unmeasured, one that reports it spins (ATA IDENTIFY word
/// 217). USB disks report no rotation, so the measurement is what finds
/// them. `None` for a disk fast enough, or unmeasured and not spinning. The
/// disk is not refused.
pub fn caution(rotation: Rotation, speed: Option<Speed>) -> Option<String> {
    match (speed, rotation) {
        (Some(speed), _) if speed.random_us > SLOWEST_READ_US => Some(format!(
            "Slow disk ({} a read): macOS may be too slow to start",
            millis(speed.random_us)
        )),
        (Some(speed), _) if speed.sequential_kib_s < SLOWEST_SEQUENTIAL_KIB_S => Some(format!(
            "Slow disk ({} MB/s): macOS may be too slow to start",
            speed.sequential_kib_s * 1024 / 1_000_000
        )),
        (Some(_), _) => None,
        (None, Rotation::Rpm(rpm)) => Some(format!(
            "Spinning disk ({rpm} rpm): macOS may be too slow to start"
        )),
        (None, Rotation::None | Rotation::Unreported) => None,
    }
}

#[cfg(test)]
mod tests;
