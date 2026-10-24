//! Observational checkpoints; none grants execution or memory authority.

/// Disjoint checkpoints in a recovered native round on its actual local Host.
/// Whole-round time includes the intervals between these points. BodyReturned
/// includes native entry/return, checked memory callbacks and finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum NativeTimingPhase {
    Begin,
    SchedulerReady,
    Prepared,
    CpuVerified,
    CodeInstalled,
    MemoryPrepared,
    BodyReturned,
    Recovered,
    End,
}

impl NativeTimingPhase {
    pub const COUNT: usize = Self::End as usize + 1;
}

/// Inclusive subcomponents of sampled rounds, not additional disjoint phases.
#[derive(Debug, Clone, Copy)]
pub enum NativeTimingWork {
    DeviceLines,
}
