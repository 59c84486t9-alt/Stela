//! Exclusive mapping service and all physical writer gates of one live domain.
use super::*;

pub(in crate::memory) struct AllWriterService<'a> {
    domain: &'a Arc<MemoryDomain>,
    generation: u64,
    // Drop gates before ending mapping/native exclusion.
    writers: monitor::FrozenWriters<'a, MemoryBacking, MemoryView, MappingAttributes>,
    _loan: MemoryServiceLoan,
}
impl AllWriterService<'_> {
    pub(in crate::memory) fn validate_current(&self) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.writers
            .validate_current()
            .map_err(|_| MemoryStatus::Domain)?;
        if self.domain.generation()? != self.generation {
            return Err(MemoryStatus::Domain);
        }
        Ok(())
    }
    pub(in crate::memory) fn generation(&self) -> u64 {
        self.generation
    }
    pub(in crate::memory) fn fail(&self) {
        self.domain.system.failed.store(true, Ordering::Release);
        self.writers.fail();
    }
}
impl MemoryDomain {
    pub(in crate::memory) fn try_all_writer_service(
        self: &Arc<Self>,
    ) -> Result<Option<AllWriterService<'_>>, MemoryStatus> {
        let loan = match self.try_service_loan()? {
            ServiceLoanAttempt::Acquired(loan) => loan,
            ServiceLoanAttempt::ExecutionBusy | ServiceLoanAttempt::ServiceBusy => return Ok(None),
        };
        let generation = self.generation()?;
        let Some(writers) = self
            .system
            .reservations
            .try_freeze_writers()
            .map_err(|_| MemoryStatus::Domain)?
        else {
            return Ok(None);
        };
        let service = AllWriterService {
            domain: self,
            generation,
            writers,
            _loan: loan,
        };
        service.validate_current()?;
        Ok(Some(service))
    }
}
