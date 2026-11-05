//! Admission and completion policy shared by the distinct execution perimeters.
//! These methods neither call providers nor grant CPU, IRQ, current or root access.
use super::*;
impl<const N: usize> State<N> {
    pub(super) fn new() -> Self {
        Self {
            #[cfg(all(target_arch = "x86_64", feature = "linux-kernel"))]
            inactive: [const { None }; MAX_CONTINUATIONS],
            jobs: [None; N],
            reservations: [0; N],
            #[cfg(target_arch = "x86_64")]
            next_reservation: 1,
            layout: Layout::Ordinary,
            stack_profile: None,
            stack_catalog: stack_requirement::Catalog::empty(),
            next: 1,
            closed: false,
            poisoned: false,
            #[cfg(target_arch = "x86_64")]
            scheduling: scheduling::Board::new(),
            #[cfg(target_arch = "x86_64")]
            resources: credits::Resources::new(),
        }
    }
    pub(super) fn enqueue(
        &mut self,
        lane: Lane,
        callback: Callback,
        context: *mut c_void,
        requested: Option<StackRequirement>,
        abandoned: bool,
    ) -> Result<u64, WorkError> {
        if self.closed || self.poisoned || abandoned {
            return Err(WorkError::Closed);
        }
        let requirement = match (self.stack_profile, requested) {
            (None, Some(_)) => return Err(WorkError::Unavailable),
            (None, None) => None,
            (Some(profile), requested) => {
                let requirement = requested.unwrap_or_else(|| profile.default_for(lane));
                if !self.stack_catalog.supports(lane, requirement) {
                    return Err(WorkError::Unavailable);
                }
                Some(requirement)
            }
        };
        let ranges = self.layout.admission(lane, N)?;
        let slot = ranges
            .into_iter()
            .flatten()
            .find(|index| self.jobs[*index].is_none() && self.reservations[*index] == 0)
            .ok_or(WorkError::Full)?;
        let sequence = self.next;
        self.next = sequence.checked_add(1).ok_or(WorkError::Exhausted)?;
        self.jobs[slot] = Some(Job {
            callback,
            context: context as usize,
            lane,
            sequence,
            running: false,
            requirement,
        });
        Ok(sequence)
    }
    pub(super) fn completed(&self, sequence: u64) -> Result<bool, WorkError> {
        if sequence == 0 || sequence >= self.next {
            return Err(WorkError::InvalidTicket);
        }
        Ok(!self
            .jobs
            .iter()
            .flatten()
            .any(|job| job.sequence == sequence))
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn select_job(
        &mut self,
        lane: Lane,
        geometry: stack_requirement::Geometry,
        abandoned: bool,
    ) -> Result<Option<(usize, Job)>, WorkError> {
        if self.poisoned || abandoned {
            return Err(WorkError::Closed);
        }
        let next = self
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, j)| {
                j.filter(|j| {
                    self.reservations[i] == 0
                        && j.lane == lane
                        && !j.running
                        && stack_requirement::compatible(j.requirement, geometry)
                })
                .map(|j| (i, j))
            })
            .min_by_key(|(_, j)| j.sequence);
        if let Some((i, _)) = next {
            self.jobs[i].as_mut().expect("selected slot").running = true;
        }
        Ok(next)
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn finish_job(
        &mut self,
        slot: usize,
        sequence: u64,
        released_stack: Option<ReleasedStackGeometry>,
    ) -> Result<(), WorkError> {
        if self.reservations.get(slot).is_none_or(|nonce| *nonce != 0) {
            return Err(WorkError::CorruptContext);
        }
        if !self
            .jobs
            .get(slot)
            .and_then(|j| *j)
            .is_some_and(|j| j.sequence == sequence && j.running)
        {
            self.poisoned = true;
            return Err(WorkError::CorruptContext);
        }
        #[cfg(target_arch = "x86_64")]
        if self
            .layout
            .admission(Lane::General, N)?
            .into_iter()
            .flatten()
            .any(|candidate| candidate == slot)
        {
            // Ledger only. No sink/callback runs on this completing Task/IF0.
            if let Some(shape) = released_stack {
                self.resources.reservation_released(shape)?;
            } else {
                self.resources.released()?;
            }
        }
        self.jobs[slot] = None;
        Ok(())
    }
}
