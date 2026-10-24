//! Warm, owner-local stepping. Each successor is reached, fetched and checked;
//! there are no linked code pointers, speculative walks or worker compilations.
use super::*;

/// Maximum checked bodies in one held publication. This also bounds profiler
/// staging; the scheduler additionally applies a finite observation deadline.
pub const MAX_NATIVE_EPOCH_BODIES: usize = 64;

/// Absolute deadline in the qualified Host::counter domain, never raw TSC or
/// the guest Clock's lead/lag adjusted domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEpochDeadline(pub u64);

#[derive(Debug, Clone, Copy)]
pub(in crate::machine::engine::shared_memory) struct Limits {
    pub max_bodies: usize,
    pub deadline: Option<NativeEpochDeadline>,
}
impl Limits {
    pub const fn single() -> Self {
        Self {
            max_bodies: 1,
            deadline: None,
        }
    }
    pub(super) fn expired(self, host: &mut dyn Host) -> bool {
        // Multiple bodies without a finite time bound are never admitted.
        self.deadline
            .is_none_or(|deadline| host.counter() >= deadline.0)
    }
}

/// Why an actual stepped epoch returned. Failed target/context operations remain
/// failures; a cold or changed successor simply returns to source scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum NativeEpochEnd {
    BodyLimit,
    Deadline,
    Service,
    MemoryFault,
    Cold,
    Source,
    Failure,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NativeEpochStatistics {
    pub rounds: u64,
    pub admitted: u64,
    pub bodies: u64,
    pub extra_bodies: u64,
    pub maximum_bodies: u64,
    /// Indexed by NativeEpochEnd; counts every observed end, including failure.
    pub ends: [u64; NativeEpochEnd::Failure as usize + 1],
}
#[cfg(feature = "native-profile")]
impl NativeEpochStatistics {
    pub(super) fn record(&mut self, limits: Limits, observation: &Observation) {
        self.rounds = self.rounds.saturating_add(1);
        self.admitted = self
            .admitted
            .saturating_add(u64::from(limits.max_bodies > 1));
        self.bodies = self.bodies.saturating_add(observation.executed_bodies);
        self.extra_bodies = self
            .extra_bodies
            .saturating_add(observation.executed_bodies.saturating_sub(1));
        self.maximum_bodies = self.maximum_bodies.max(observation.executed_bodies);
        let count = &mut self.ends[observation.epoch_end as usize];
        *count = count.saturating_add(1);
    }
}

impl NativeRun<'_> {
    pub(super) fn enter_epoch(
        &mut self,
        host: &mut dyn Host,
        authority: &NativeSystemTarget,
        execution: &crate::memory::domain::MemoryExecutionSession,
        observation: &mut Observation,
    ) -> Result<(), MemoryStatus> {
        let mut next = Arc::clone(&self.artifact);
        loop {
            if !self.enter_body(host, authority, execution, next, observation)? {
                break;
            }
            if observation.memory_fault.is_some() {
                observation.epoch_end = NativeEpochEnd::MemoryFault;
                break;
            }
            let ordinary = matches!(observation.native,
                Some(NativeExit::Exit {kind, ..}) if matches!(ExitKind::try_from(kind),
                    Ok(ExitKind::Fallthrough | ExitKind::Direct | ExitKind::Indirect |
                       ExitKind::Call | ExitKind::Return)));
            if !ordinary {
                observation.epoch_end = NativeEpochEnd::Service;
                break;
            }
            if self.executed_bodies as usize >= self.limits.max_bodies.min(MAX_NATIVE_EPOCH_BODIES)
            {
                observation.epoch_end = NativeEpochEnd::BodyLimit;
                break;
            }
            if self.limits.expired(host) {
                observation.epoch_end = NativeEpochEnd::Deadline;
                break;
            }
            #[cfg(feature = "native-profile")]
            let measured = host.native_timing_work_start(Work::WarmSource);
            let successor = self.warm_successor(execution);
            #[cfg(feature = "native-profile")]
            if let Some(started) = measured {
                host.native_timing_work_end(Work::WarmSource, started);
            }
            let (index, candidate) = match successor? {
                Ok(candidate) => candidate,
                Err(reason) => {
                    observation.epoch_end = reason;
                    break;
                }
            };
            // Source lookup/walk/copy can itself consume the quantum. Never
            // promote or enter that successor after the fresh deadline check.
            if self.limits.expired(host) {
                observation.epoch_end = NativeEpochEnd::Deadline;
                break;
            }
            self.memory.artifacts.reuse(index);
            next = candidate;
        }
        Ok(())
    }

    /// A failed speculative *validation of the reached successor* is a yield,
    /// not an exception: the ordinary scheduler owns that next instruction.
    /// Owner/domain corruption is never converted into an innocent cache miss.
    pub(super) fn warm_successor(
        &self,
        execution: &crate::memory::domain::MemoryExecutionSession,
    ) -> Result<Result<(usize, Arc<Artifact>), NativeEpochEnd>, MemoryStatus> {
        let Some(controls) = self.memory.artifacts.controls() else {
            return Ok(Err(NativeEpochEnd::Cold));
        };
        let pc = *self.pc;
        if !pc.is_multiple_of(4) {
            return Ok(Err(NativeEpochEnd::Source));
        }
        let loan = execution.checked_execution(&self.memory.memory)?;
        // SAFETY: the preceding body has returned, no guest or Host service
        // runs in this probe, all other PEs are Off, and the native-round caller
        // excludes unjoined code/MMU writers. The pin alone is not that proof.
        let source = match unsafe {
            source::ExecuteTranslation::first(
                &self.memory.ram,
                controls,
                loan,
                pc,
                #[cfg(feature = "native-profile")]
                &self.memory.source,
            )
        } {
            Ok(source) => source,
            Err(source::FetchFailure::Refused(MemoryStatus::Domain)) => {
                return Err(MemoryStatus::Domain);
            }
            Err(_) => return Ok(Err(NativeEpochEnd::Source)),
        };
        let first = source.first_word();
        let guarded = source.guarded();
        if *self.btype != 0
            && guarded
            && !source::target_accepts(
                first,
                *self.btype,
                controls.translation.sctlr,
                controls.requester.el,
            )
        {
            return Ok(Err(NativeEpochEnd::Source));
        }
        let mut key = self.artifact.key.clone();
        key.pc = pc;
        key.guarded = guarded;
        let Some((index, candidate)) = self.memory.artifacts.candidate(&key) else {
            return Ok(Err(NativeEpochEnd::Cold));
        };
        let bytes = candidate.source.len();
        if bytes == 0 || !bytes.is_multiple_of(4) || bytes > super::super::super::window(pc) {
            return Err(MemoryStatus::Domain);
        }
        let mut staging = [0; super::super::super::MAX_BLOCK_BYTES as usize];
        let input = staging.get_mut(..bytes).ok_or(MemoryStatus::Domain)?;
        match source.read_into(input) {
            Ok(()) => {}
            Err(MemoryStatus::Domain) => return Err(MemoryStatus::Domain),
            Err(_) => return Ok(Err(NativeEpochEnd::Source)),
        }
        if input != candidate.source.as_slice() {
            return Ok(Err(NativeEpochEnd::Source));
        }
        Ok(Ok((index, candidate)))
    }
}
