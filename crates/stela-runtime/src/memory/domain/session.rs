//! Storage preparation retained under one real mapping-exclusion loan. This
//! caches no guest permissions, effective policy or successful health checks.
use super::*;

/// Owned pin for several checked calls. A profile clone belongs to exactly the
/// domain held by this loan, and publication cannot replace it until drop.
pub(crate) struct MemoryExecutionSession {
    execution: MemoryExecutionLoan,
    profile: MemoryProfile,
}
impl MemoryExecutionSession {
    /// Borrow the actual mapping pin after checking membership and live health.
    /// This grants neither guest permissions nor exclusion of RAM/PTE writers.
    pub(crate) fn checked_execution<P: DataPolicy>(
        &self,
        thread: &MemoryThread<P>,
    ) -> Result<&MemoryExecutionLoan, MemoryStatus> {
        self.check_thread(thread)?;
        Ok(&self.execution)
    }

    pub(super) fn check_thread<P: DataPolicy>(
        &self,
        thread: &MemoryThread<P>,
    ) -> Result<(), MemoryStatus> {
        self.execution.check_thread_domain(thread)
    }
}

impl<P: DataPolicy> MemoryThread<P> {
    pub(crate) fn execution_session(&self) -> Result<MemoryExecutionSession, MemoryStatus> {
        let execution = self.execution_loan()?;
        // Clone while the actual loan excludes mapping/profile publication.
        // The owning Arc and this copy outlive every subsequent body borrow.
        let profile = self.domain.profile()?;
        Ok(MemoryExecutionSession { execution, profile })
    }

    pub(crate) fn prepare_native_system_in<'a>(
        &'a mut self,
        requirements: MemoryRequirements,
        authority: &'a crate::platform::cpu::system::NativeSystemTarget,
        session: &'a MemoryExecutionSession,
    ) -> Result<CheckedMemoryEntry<'a, P>, MemoryStatus> {
        if self.domain.role != DomainRole::NativeSystemRam
            || !authority.target().supports(self.domain.target)
        {
            return Err(MemoryStatus::Unsupported);
        }
        authority
            .revalidate()
            .map_err(|_| MemoryStatus::Unsupported)?;
        session.check_thread(self)?;
        // Keep the complete effective policy and requirement checks per body.
        // Only the immutable, pinned storage geometry avoids another clone.
        let mut entry = self.prepare_body_with_profile(requirements, Some(&session.profile))?;
        entry.native_system = Some(authority);
        entry.session = Some(session);
        Ok(entry)
    }

    /// As with_checked_view, using the caller's authentic retained domain pin.
    /// All live health and callback finalization checks still run each call.
    ///
    /// # Safety
    /// The exact with_checked_view invocation/staging contract applies.
    pub(super) unsafe fn with_checked_view_in<R>(
        &mut self,
        session: &MemoryExecutionSession,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        self.domain.check_data_execution()?;
        session.check_thread(self)?;
        // SAFETY: the actual matching loan outlives callback finalization and
        // excludes publication; the caller retains disjoint staging/policy.
        let (result, finalization) = unsafe { self.invoke_memory_view(callback) };
        finalization.map(|()| result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    use core::cell::Cell;

    fn fixture(system: &Arc<MemorySystem>) -> (Arc<MemoryDomain>, MemoryThread<MemoryControls>) {
        let domain = MemoryDomain::new_for_address_space(
            7,
            Arc::clone(system),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap();
        let policy = MemoryControls::new(
            LowerAddressProfile::new(44, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let thread = domain.thread(policy);
        (domain, thread)
    }

    #[test]
    fn session_reuses_one_real_pin_and_excludes_publication_until_drop() {
        let system = MemorySystem::new(16, 8).unwrap();
        let (domain, mut thread) = fixture(&system);
        let session = thread.execution_session().unwrap();
        for value in [19, 37] {
            assert_eq!(domain.state.lock().unwrap().native_loans, 1);
            // SAFETY: no retained pointers or guest accesses in this callback.
            assert_eq!(
                unsafe { thread.with_checked_view_in(&session, |_| value) },
                Ok(value)
            );
            assert_eq!(domain.state.lock().unwrap().native_loans, 1);
            assert!(matches!(
                domain.try_service_loan().unwrap(),
                ServiceLoanAttempt::ExecutionBusy
            ));
        }
        drop(session);
        assert_eq!(domain.state.lock().unwrap().native_loans, 0);
        assert!(matches!(
            domain.try_service_loan().unwrap(),
            ServiceLoanAttempt::Acquired(_)
        ));
        // Existing invocation still acquires and drops its own pin.
        assert_eq!(
            unsafe { thread.with_checked_view(|_| domain.state.lock().unwrap().native_loans) },
            Ok(1)
        );
        assert_eq!(domain.state.lock().unwrap().native_loans, 0);
    }

    #[test]
    fn equal_address_space_and_shared_system_do_not_authorize_foreign_session() {
        let system = MemorySystem::new(16, 8).unwrap();
        let (_, first) = fixture(&system);
        let (_, mut second) = fixture(&system);
        let other_system = MemorySystem::new(16, 8).unwrap();
        let (_, mut third) = fixture(&other_system);
        let session = first.execution_session().unwrap();
        for thread in [&mut second, &mut third] {
            let called = Cell::new(false);
            assert_eq!(
                unsafe { thread.with_checked_view_in(&session, |_| called.set(true)) },
                Err(MemoryStatus::Domain)
            );
            assert!(!called.get());
        }
    }

    #[test]
    fn retained_profile_still_validates_each_new_requirement_without_effects() {
        let system = MemorySystem::new(16, 8).unwrap();
        let (_, mut thread) = fixture(&system);
        let session = thread.execution_session().unwrap();
        let cases = [
            MemoryRequirements::default(),
            MemoryRequirements {
                required_host_caps: stela_compiler::context::memory::host_caps::CX16,
                ..Default::default()
            },
            MemoryRequirements {
                required_profile: 1 << 31,
                ..Default::default()
            },
            MemoryRequirements::default(),
        ];
        for requirements in cases {
            let expected = thread.prepare(requirements).err();
            let actual = thread
                .prepare_body_with_profile(requirements, Some(&session.profile))
                .err();
            assert_eq!(actual, expected);
            assert_eq!(thread.domain.state.lock().unwrap().native_loans, 1);
        }
    }

    #[test]
    fn session_checks_live_poison_before_and_after_each_callback() {
        let system = MemorySystem::new(16, 8).unwrap();
        let (_, mut thread) = fixture(&system);
        let session = thread.execution_session().unwrap();
        let result = unsafe {
            thread.with_checked_view_in(&session, |_| {
                system.failed.store(true, Ordering::Release);
                37
            })
        };
        assert_eq!(result, Err(MemoryStatus::Domain));
        let called = Cell::new(false);
        assert_eq!(
            unsafe { thread.with_checked_view_in(&session, |_| called.set(true)) },
            Err(MemoryStatus::Domain)
        );
        assert!(!called.get());
    }

    #[test]
    fn malformed_view_poisons_session_instead_of_returning_body_result() {
        let system = MemorySystem::new(16, 8).unwrap();
        let (_, mut thread) = fixture(&system);
        let session = thread.execution_session().unwrap();
        assert_eq!(
            unsafe {
                thread.with_checked_view_in(&session, |view| {
                    view.version ^= 1;
                    37
                })
            },
            Err(MemoryStatus::Domain)
        );
        assert!(system.failed.load(Ordering::Acquire));
    }
}
