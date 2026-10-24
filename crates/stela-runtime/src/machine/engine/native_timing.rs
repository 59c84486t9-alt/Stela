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

/// Immutable attribution for an actually recovered native body. Deferred
/// service terminals have not retired; a failed access is a separate attempt.
/// Native byte intervals are static source attribution, not executed x86 counts.
#[derive(Debug, Clone, Copy)]
pub struct NativeInstructionSample<'a> {
    pub source: &'a [u8],
    pub source_map: &'a [(stela_compiler::GuestAddress, usize)],
    pub native_bytes: usize,
    pub register_spans: &'a [stela_compiler::block::profile::RegisterSpan],
    pub retired: u64,
    pub faulting: bool,
    pub deferred_terminal: bool,
}
