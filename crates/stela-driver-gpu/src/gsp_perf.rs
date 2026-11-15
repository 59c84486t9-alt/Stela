//! `GPU PERF`: the GPU's performance state as GSP-RM reports it. nouveau
//! asks RM every second for the current P-state and for its PMU monitor's
//! GPC and memory clock samples (`nvkm/subdev/gsp/rm/r535/perf.c`) and adds
//! them to a report this module takes once a beat. The line comes at the
//! first beat after GSP starts and then only when the state changed, so an
//! idle desktop stays quiet. A control RM refused stays named with its
//! errno on every line, as the state it would give is unknown.
use alloc::{format, string::String};
use core::{
    fmt,
    sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering},
};

/// `include/nvkm/core/counts.h`: `struct nvkm_perf_report`, which nouveau
/// updates only atomically.
#[repr(C)]
pub struct Report {
    started: AtomicU32,
    rounds: AtomicU32,
    pstate: AtomicU32,
    pstates: AtomicU32,
    gpc_samples: AtomicU32,
    gpc_min_mhz: AtomicU32,
    gpc_max_mhz: AtomicU32,
    mem_min_mhz: AtomicU32,
    mem_max_mhz: AtomicU32,
    pstate_status: AtomicI32,
    clk_status: AtomicI32,
    reserved: AtomicU32,
    gpc_sum_mhz: AtomicU64,
}

impl Report {
    /// As nouveau defines it: nothing sampled yet.
    pub const fn new() -> Self {
        Self {
            started: AtomicU32::new(0),
            rounds: AtomicU32::new(0),
            pstate: AtomicU32::new(0),
            pstates: AtomicU32::new(0),
            gpc_samples: AtomicU32::new(0),
            gpc_min_mhz: AtomicU32::new(u32::MAX),
            gpc_max_mhz: AtomicU32::new(0),
            mem_min_mhz: AtomicU32::new(u32::MAX),
            mem_max_mhz: AtomicU32::new(0),
            pstate_status: AtomicI32::new(0),
            clk_status: AtomicI32::new(0),
            reserved: AtomicU32::new(0),
            gpc_sum_mhz: AtomicU64::new(0),
        }
    }

    /// What nouveau sampled since the last take, cleared; `None` before GSP
    /// started or when no round ran since.
    pub fn take(&self) -> Option<Taken> {
        if self.started.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let rounds = self.rounds.swap(0, Ordering::Relaxed);
        let samples = self.gpc_samples.swap(0, Ordering::Relaxed);
        let sum = self.gpc_sum_mhz.swap(0, Ordering::Relaxed);
        let gpc = (
            self.gpc_min_mhz.swap(u32::MAX, Ordering::Relaxed),
            self.gpc_max_mhz.swap(0, Ordering::Relaxed),
        );
        let mem = (
            self.mem_min_mhz.swap(u32::MAX, Ordering::Relaxed),
            self.mem_max_mhz.swap(0, Ordering::Relaxed),
        );
        let pstates = self.pstates.swap(0, Ordering::Relaxed);
        if rounds == 0 {
            return None;
        }
        let mean = sum.checked_div(u64::from(samples)).unwrap_or(0) as u32;
        Some(Taken {
            rounds,
            pstate: self.pstate.load(Ordering::Relaxed),
            pstates,
            gpc: (samples != 0 && gpc.0 <= gpc.1).then_some(Clocks {
                min: gpc.0,
                mean,
                max: gpc.1,
            }),
            samples,
            mem: (mem.0 <= mem.1).then_some((mem.0, mem.1)),
            pstate_status: self.pstate_status.load(Ordering::Relaxed),
            clk_status: self.clk_status.load(Ordering::Relaxed),
        })
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

/// GPC clock samples in MHz.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Clocks {
    pub min: u32,
    pub mean: u32,
    pub max: u32,
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
    pub gpc: Option<Clocks>,
    /// GPC clock samples.
    pub samples: u32,
    /// Memory clock samples' lowest and highest, in MHz.
    pub mem: Option<(u32, u32)>,
    /// The errno of a P-state control RM refused, else zero.
    pub pstate_status: i32,
    /// The errno of a clock control RM refused, else zero.
    pub clk_status: i32,
}

/// Clock buckets for a change, in MHz: finer steps are the policy's noise.
const BUCKET_MHZ: u32 = 50;

impl Taken {
    /// What a change is judged by: the P-states, the clock range in
    /// buckets and the controls' statuses, not counts or the mean.
    fn state(&self) -> [u64; 4] {
        let bucket = |mhz: u32| u64::from(mhz / BUCKET_MHZ);
        let gpc = self
            .gpc
            .map_or(u64::MAX, |gpc| bucket(gpc.min) << 32 | bucket(gpc.max));
        let mem = self
            .mem
            .map_or(u64::MAX, |(min, max)| bucket(min) << 32 | bucket(max));
        let pstates = u64::from(self.pstate) << 32 | u64::from(self.pstates);
        let statuses =
            u64::from(self.pstate_status as u32) << 32 | u64::from(self.clk_status as u32);
        [pstates, gpc, mem, statuses]
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

/// `pstate=P8 seen=P0+P8 gpc_mhz=min/mean/max mem_mhz=min/max samples=N
/// rounds=N`, with `unknown(error E)` for what a refused control gives and
/// `-` for what RM sampled nothing of.
impl fmt::Display for Taken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pstate_status {
            0 => write!(
                f,
                "pstate={} seen={}",
                Pstates(self.pstate),
                Pstates(self.pstates)
            )?,
            error => write!(f, "pstate=unknown(error {error})")?,
        }
        if self.clk_status != 0 {
            write!(f, " clocks=unknown(error {})", self.clk_status)?;
        } else {
            match self.gpc {
                Some(Clocks { min, mean, max }) => write!(f, " gpc_mhz={min}/{mean}/{max}")?,
                None => f.write_str(" gpc_mhz=-")?,
            }
            match self.mem {
                Some((min, max)) => write!(f, " mem_mhz={min}/{max}")?,
                None => f.write_str(" mem_mhz=-")?,
            }
        }
        write!(f, " samples={} rounds={}", self.samples, self.rounds)
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
        value: UnsafeCell<Option<[u64; 4]>>,
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
        pub fn replace(&self, value: [u64; 4]) -> Option<[u64; 4]> {
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
