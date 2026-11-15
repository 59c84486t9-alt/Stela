//! `GPU PERF`: the GPU's performance state as GSP-RM reports it. nouveau
//! asks RM every second for the current P-state
//! (`nvkm/subdev/gsp/rm/r535/perf.c`) and adds it to a report this module
//! takes once a beat. The line comes at the first beat after GSP starts and
//! then only when the state changed, so an idle desktop stays quiet. If RM
//! refused the control, every line names its errno, as the state is unknown.
//! Clocks are not read: the 570.144 layout of RM's clock sample control is
//! not in the tree, and RM refused the 615.78.08 one.
use alloc::{format, string::String};
use core::{
    fmt,
    sync::atomic::{AtomicI32, AtomicU32, Ordering},
};

/// `include/nvkm/core/counts.h`: `struct nvkm_perf_report`, which nouveau
/// updates only atomically.
#[repr(C)]
pub struct Report {
    started: AtomicU32,
    rounds: AtomicU32,
    pstate: AtomicU32,
    pstates: AtomicU32,
    pstate_status: AtomicI32,
}

impl Report {
    /// As nouveau defines it: nothing sampled yet.
    pub const fn new() -> Self {
        Self {
            started: AtomicU32::new(0),
            rounds: AtomicU32::new(0),
            pstate: AtomicU32::new(0),
            pstates: AtomicU32::new(0),
            pstate_status: AtomicI32::new(0),
        }
    }

    /// What nouveau sampled since the last take, cleared; `None` before GSP
    /// started or when no round ran since.
    pub fn take(&self) -> Option<Taken> {
        if self.started.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let rounds = self.rounds.swap(0, Ordering::Relaxed);
        let pstates = self.pstates.swap(0, Ordering::Relaxed);
        (rounds != 0).then(|| Taken {
            rounds,
            pstate: self.pstate.load(Ordering::Relaxed),
            pstates,
            status: self.pstate_status.load(Ordering::Relaxed),
        })
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

/// One beat's samples.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Taken {
    /// Rounds that asked RM.
    pub rounds: u32,
    /// The current P-state's bit (`NV2080_CTRL_PERF_PSTATES_P0` is bit 0),
    /// zero while unknown.
    pub pstate: u32,
    /// Every P-state bit a round saw.
    pub pstates: u32,
    /// The errno of the control RM refused, else zero.
    pub status: i32,
}

impl Taken {
    /// What a change is judged by: the P-states and the status, not the
    /// count of rounds.
    fn state(&self) -> [u64; 2] {
        [
            u64::from(self.pstate) << 32 | u64::from(self.pstates),
            u64::from(self.status as u32),
        ]
    }
}

/// `P0+P8` for a set of P-state bits.
struct Pstates(u32);

impl fmt::Display for Pstates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for index in (0..16).filter(|index| self.0 & 1 << index != 0) {
            if !first {
                f.write_str("+")?;
            }
            first = false;
            write!(f, "P{index}")?;
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// `pstate=P8 seen=P5+P8 rounds=N`, or `pstate=unknown(error E) rounds=N`.
impl fmt::Display for Taken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            0 => write!(
                f,
                "pstate={} seen={}",
                Pstates(self.pstate),
                Pstates(self.pstates)
            )?,
            error => write!(f, "pstate=unknown(error {error})")?,
        }
        write!(f, " rounds={}", self.rounds)
    }
}

/// The state the last line reported.
pub struct Reported {
    last: spin_cell::Cell,
}

impl Reported {
    pub const fn new() -> Self {
        Self {
            last: spin_cell::Cell::new(),
        }
    }

    /// `GPU PERF …` for `taken` when it is the first or its state changed
    /// since the last line.
    pub fn line(&self, taken: &Taken) -> Option<String> {
        self.last
            .replace(taken.state())
            .is_none_or(|last| last != taken.state())
            .then(|| format!("GPU PERF {taken}"))
    }
}

impl Default for Reported {
    fn default() -> Self {
        Self::new()
    }
}

/// The last reported state behind a spin lock: a beat's report is the only
/// writer, so it never waits in practice.
mod spin_cell {
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    };

    pub struct Cell {
        held: AtomicBool,
        value: UnsafeCell<Option<[u64; 2]>>,
    }

    // SAFETY: `replace` holds `held` for every access to the value.
    unsafe impl Sync for Cell {}

    impl Cell {
        pub const fn new() -> Self {
            Self {
                held: AtomicBool::new(false),
                value: UnsafeCell::new(None),
            }
        }

        /// Stores `value`, giving the one before.
        pub fn replace(&self, value: [u64; 2]) -> Option<[u64; 2]> {
            while self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            // SAFETY: `held` excludes every other access until released.
            let last = unsafe { (*self.value.get()).replace(value) };
            self.held.store(false, Ordering::Release);
            last
        }
    }
}

#[cfg(test)]
mod tests;
