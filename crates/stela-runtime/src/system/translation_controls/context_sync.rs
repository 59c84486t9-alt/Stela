//! Control generation for exception context synchronization.
use super::{
    ContextSynchronizationCause, ContextSynchronizationRequest, ControlError, FetchedInstruction,
    PreparedPublication, TranslationControls, TranslationServices, check_execution_state,
};
use crate::system::state::SystemState;

impl TranslationControls {
    /// The canonical post-native consumer retains the same original state,
    /// source, outer and PE loans. This method only reserves its genuine CSE
    /// producer; the exception plan separately validates and commits CPU state.
    pub(crate) fn prepare_exception_context<'a, S: TranslationServices>(
        &'a mut self,
        fetched: &FetchedInstruction,
        state: &SystemState,
        cause: ContextSynchronizationCause,
        services: &'a mut S,
    ) -> Result<PreparedContextSynchronization<'a, S::Prepared<'a>>, ControlError> {
        check_execution_state(state)?;
        self.check_services(services)?;
        self.check_site(fetched)?;
        if !cause.matches_source(fetched.word()) {
            // Authenticated return/failure needs its feature-present original
            // PAuth service before it can select this synchronization cause.
            return Err(ControlError::Unavailable(
                "exception source needs another actual context service",
            ));
        }
        services
            .validate_source(&self.current_snapshot(), fetched.source, state)
            .map_err(ControlError::Unavailable)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlError::GenerationExhausted)?;
        let before = self.current_snapshot();
        let mut after = before.clone();
        after.generation = next_generation;
        let prepared = services
            .prepare_context_synchronization(ContextSynchronizationRequest {
                before,
                after,
                source: fetched.source,
                cpu: self.profile.cpu,
                state,
                cause,
            })
            .map_err(ControlError::Unavailable)?;
        Ok(PreparedContextSynchronization {
            owner: self,
            prepared,
            next_generation,
        })
    }
}

/// Same original mutable controls and actual prepared source/publication gates.
/// No PC, return target, cloned SystemState or detached retirement owner exists.
pub(crate) struct PreparedContextSynchronization<'a, P: PreparedPublication> {
    owner: &'a mut TranslationControls,
    prepared: P,
    next_generation: u64,
}
impl<'a, P: PreparedPublication> PreparedContextSynchronization<'a, P> {
    /// Recover the SAME controls after the actual publication attempt. A failed
    /// bank remains poisoned; returning its loan grants neither retry nor entry.
    #[must_use = "recover the original controls and inspect exact publication outcome"]
    pub(crate) fn commit(self) -> (&'a mut TranslationControls, Result<(), ControlError>) {
        let Self {
            owner,
            prepared,
            next_generation,
        } = self;
        if let Err(error) = prepared.commit() {
            owner.poisoned = true;
            return (
                owner,
                Err(ControlError::Publication {
                    register_committed: false,
                    progress: error.progress,
                    reason: error.reason,
                }),
            );
        }
        owner.generation = next_generation;
        (owner, Ok(()))
    }
}
